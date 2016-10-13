class LogStash::Filters::Grok::TimeoutEnforcer
  attr_reader :running
  
  def initialize(logger, timeout_nanos)
    @logger = logger
    @running = true
    @timeout_nanos = timeout_nanos

    # Stores running matches with their start time, this is used to cancel long running matches
    # Is a map of Thread => start_time
    @timer_mutex = Mutex.new
    @threads_to_start_time = {}        
  end

  def grok_till_timeout(event, grok, field, value)
    begin
      thread = java.lang.Thread.currentThread()
      start_thread_groking(thread)
      yield
    rescue InterruptedRegexpError => e
      raise ::LogStash::Filters::Grok::TimeoutException.new(grok, field, value)
    ensure
      stop_thread_groking(thread)
      # Clear any interrupts from any previous invocations that were not caught by Joni
      thread.interrupted
    end
  end

  def start_thread_groking(thread)
    # Clear any interrupts from any previous invocations that were not caught by Joni
    thread.interrupted
    @timer_mutex.synchronize do
      @threads_to_start_time[thread] = java.lang.System.nanoTime()
    end
  end

  def stop_thread_groking(thread)
    @timer_mutex.synchronize do
      @threads_to_start_time.delete(thread)
    end
  end

  def cancel_timed_out!
    @timer_mutex.synchronize do
      @threads_to_start_time.each do |thread,start_time|
        now = java.lang.System.nanoTime # save ourselves some nanotime calls
        elapsed = java.lang.System.nanoTime - start_time
        if elapsed > @timeout_nanos
          elapsed_millis = elapsed / 1000
          thread.interrupt()
          # Ensure that we never attempt to cancel this thread twice in the event
          # of weird races
          stop_thread_groking(thread)
        end
      end
    end
  end

  def start!
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
end
