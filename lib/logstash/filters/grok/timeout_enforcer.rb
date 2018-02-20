class LogStash::Filters::Grok::TimeoutEnforcer
  def initialize(logger, timeout_nanos)
    @logger = logger
    @running = java.util.concurrent.atomic.AtomicBoolean.new(false)
    @timeout_nanos = timeout_nanos

    # Stores running matches with their start time, this is used to cancel long running matches
    # Is a map of Thread => start_time
    @threads_to_start_time = java.util.concurrent.ConcurrentHashMap.new
  end

  def running
    @running.get()
  end

  def grok_till_timeout(grok, field, value)
    begin
      thread = java.lang.Thread.currentThread()
      @threads_to_start_time.put(thread, java.lang.System.nanoTime)
      grok.execute(value)
    rescue InterruptedRegexpError, java.lang.InterruptedException => e
      raise ::LogStash::Filters::Grok::TimeoutException.new(grok, field, value)
    ensure
      # If the regexp finished, but interrupt was called after, we'll want to
      # clear the interrupted status anyway
      @threads_to_start_time.remove(thread)
      thread.interrupted
    end
  end

  def start!
    @running.set(true)
    @timer_thread = Thread.new do
      while @running.get()
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
    @running.set(false)
    # Check for the thread mostly for a fast start/shutdown scenario
    @timer_thread.join if @timer_thread
  end

  private

  def cancel_timed_out!
    now = java.lang.System.nanoTime # save ourselves some nanotime calls
    @threads_to_start_time.keySet.each do |thread|
      # Use compute to lock this value
      @threads_to_start_time.computeIfPresent(thread) do |thread, start_time|
        if start_time < now && now - start_time > @timeout_nanos
          thread.interrupt
          nil # Delete the key
        else
          start_time # preserve the key
        end
      end
    end
  end

end
