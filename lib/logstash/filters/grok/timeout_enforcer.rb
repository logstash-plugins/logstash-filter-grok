java_import java.util.concurrent.locks.ReentrantLock

class LogStash::Filters::Grok::TimeoutEnforcer
  attr_reader :running

  def initialize(logger, timeout_nanos)
    @logger = logger
    @running = false
    @timeout_nanos = timeout_nanos

    # Stores running matches with their start time, this is used to cancel long running matches
    # Is a map of Thread => start_time
    @threads_to_start_time = {}
    @state_lock = java.util.concurrent.locks.ReentrantLock.new
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
      # It may appear that this should go in #stop_thread_groking but that would actually
      # break functionality! If this were moved there we would clear the interrupt
      # immediately after setting it in #cancel_timed_out, hence this MUST be here
      thread.interrupted
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
    thread.interrupted
    synchronize do
      @threads_to_start_time[thread] = java.lang.System.nanoTime()
    end
  end

  def stop_thread_groking(thread)
    synchronize do
      @threads_to_start_time.delete(thread)
    end
  end

  def cancel_timed_out!
    synchronize do
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

  # We use this instead of a Mutex because JRuby mutexes are interruptible
  # We actually don't want that behavior since we always clear the interrupt in
  # grok_till_timeout
  def synchronize
    # The JRuby Mutex uses lockInterruptibly which is what we DO NOT want
    @state_lock.lock()
    yield
  ensure
    @state_lock.unlock()
  end


end
