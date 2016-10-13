class LogStash::Filters::Grok::TimeoutException < Exception
  attr_reader :grok, :field, :value
  
  def initialize(grok=nil, field=nil, value=nil)
    @field = field
    @value = value
    @grok = grok
  end

  def message
    "Timeout executing grok '#{@grok.pattern}' against field '#{field}' with value '#{trunc_value}'!"
  end

  def trunc_value
    if value.size <= 255 # If no more than 255 chars
      value
    else
      "Value too large to output (#{value.bytesize} bytes)! First 255 chars are: #{value[0..255]}"
    end
  end
end
