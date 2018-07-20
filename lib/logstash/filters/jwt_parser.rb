# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "jwt"

class LogStash::Filters::Example < LogStash::Filters::Base
  config_name "jwt_parser"
  
  # Replace the message with this value.
  config :token, :validate => :string
  

  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)
    @logger.warn("jwt_parser filter: reveived event", :type => event["type"])
    # IMPORTANT: set nil as password parameter
    decoded_token = JWT.decode token, nil, false
    event['token'] = decoded_token

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Example
