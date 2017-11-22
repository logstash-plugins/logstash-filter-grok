class LogStash::Filters::Grok::TimeoutEnforcer
  attr_reader :running

  def initialize(logger, timeout_nanos)
    @logger = logger
    @running = false
    @timeout_nanos = timeout_nanos

    # Stores running matches with their start time, this is used to cancel long running matches
    # Is a map of Thread => start_time
    @threads_to_start_time = java.util.concurrent.ConcurrentHashMap.new
    @cancel_mutex = Mutex.new
  end

  def grok_till_timeout(grok, field, value)
    begin
      thread = java.lang.Thread.currentThread()
      start_thread_groking(thread)
      grok.execute(value)
    rescue InterruptedRegexpError => e
      raise ::LogStash::Filters::Grok::TimeoutException.new(grok, field, value)
    ensure
      unless stop_thread_groking(thread)
        @cancel_mutex.lock
        begin
          # Clear any interrupts from any previous invocations that were not caught by Joni
          # It may appear that this should go in #stop_thread_groking but that would actually
          # break functionality! If this were moved there we would clear the interrupt
          # immediately after setting it in #cancel_timed_out, hence this MUST be here
          java.lang.Thread.interrupted
        ensure
          @cancel_mutex.unlock
        end
      end
    end
  end

  def start!
    @running = true
    @timer_thread = Thread.new do
      while @running
        begin
          cancel_timed_out!
        rescue Exception => e
          @logger.error("Error while attempting to check/cancel excessively long grok patterns",
                        :message => e.message,
                        :class => e.class.name,
                        :backtrace => e.backtrace
                       )
        end
        sleep 0.25
      end
    end
  end

  def stop!
    @running = false
    # Check for the thread mostly for a fast start/shutdown scenario
    @timer_thread.join if @timer_thread
  end

  private

  # These methods are private in large part because if they aren't called
  # in specific sequence and used together in specific ways the interrupt
  # behavior will be incorrect. Do NOT use or modify these methods unless
  # you know what you are doing!

  def start_thread_groking(thread)
    # Clear any interrupts from any previous invocations that were not caught by Joni
    java.lang.Thread.interrupted
    @threads_to_start_time.put(thread, java.lang.System.nanoTime)
  end

  # Returns falsy in case there was no Grok execution in progress for the thread
  def stop_thread_groking(thread)
    @threads_to_start_time.remove(thread)
  end

  def cancel_timed_out!
    now = java.lang.System.nanoTime # save ourselves some nanotime calls
    @threads_to_start_time.entry_set.each do |entry|
      start_time = entry.get_value
      if start_time < now && now - start_time > @timeout_nanos
        thread  = entry.get_key
        # Ensure that we never attempt to cancel this thread unless a Grok execution is in progress
        # Theoretically there is a race condition here in case the entry's grok action changed
        # between evaluating the above condition on the start_time and calling stop_thread_groking
        # Practically this is impossible, since it would require a whole loop of writing to an
        # output, pulling new input events and starting a new Grok execution in worker thread
        # in between the above `if start_time < now && now - start_time > @timeout_nanos` and
        # the call to `stop_thread_groking`.
        if stop_thread_groking(thread)
          @cancel_mutex.lock
          begin
            thread.interrupt()
          ensure
            @cancel_mutex.unlock
          end
        end
      end
    end
  end

end
