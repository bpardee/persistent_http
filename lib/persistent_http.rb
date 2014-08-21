require 'persistent_http/connection'
require 'persistent_http/version'
require 'gene_pool'

##
# Persistent connections for Net::HTTP
#
# PersistentHTTP maintains a connection pool of Net::HTTP persistent connections.
# When connections fail due to resets or bad responses, the connection is renewed
# and the request is retried per RFC 2616 (POST requests will only get retried if
# the :force_retry option is set to true).
#
# Example:
#
#   @@persistent_http = PersistentHTTP.new(
#     :name         => 'MyHTTPClient',
#     :logger       => Rails.logger,
#     :pool_size    => 10,
#     :warn_timeout => 0.25,
#     :force_retry  => true,
#     :url          => 'https://www.example.com/echo/foo'  # equivalent to :use_ssl => true, :host => 'www.example.com', :default_path => '/echo/foo'
#   )
#
#   def send_get_message
#     response = @@persistent_http.request
#     ... Handle response as you would a normal Net::HTTPResponse ...
#   end
#
#   def send_post_message
#     request = Net::HTTP::Post.new('/perform_service)
#     ... Modify request as needed ...
#     response = @@persistent_http.request(request)
#     ... Handle response as you would a normal Net::HTTPResponse ...
#   end

class PersistentHTTP

  ##
  # Error class for errors raised by PersistentHTTP.  Various
  # SystemCallErrors are re-raised with a human-readable message under this
  # class.
  class Error < StandardError; end

  ##
  # Connection will be renewed if it hasn't been used in this amount of time.  Defaults to 10 seconds.
  attr_reader :idle_timeout

  ##
  # Logger for message logging.
  attr_accessor :logger

  ##
  # A name for this connection.  Allows you to keep your connections apart
  # from everybody else's.
  attr_reader :name

  ##
  # Seconds to wait for an available connection before a Timeout::Error is raised
  attr_accessor :pool_timeout

  ##
  # The maximum size of the connection pool
  attr_reader :pool_size

  ##
  # The threshold in seconds for checking out a connection at which a warning
  # will be logged via the logger
  attr_reader :warn_timeout

  ##
  # Host for the Net:HTTP connection
  attr_reader :host

  ##
  # Port for the Net:HTTP connection
  attr_reader :port

  ##
  # Default path for the request
  attr_accessor :default_path

  ##
  # Creates a new PersistentHTTP.
  #
  # Set +name+ to keep your connections apart from everybody else's.  Not
  # required currently, but highly recommended.  Your library name should be
  # good enough.  This parameter will be required in a future version.
  #
  # +proxy+ may be set to a URI::HTTP or :ENV to pick up proxy options from
  # the environment.  See proxy_from_env for details.
  #
  # In order to use a URI for the proxy you'll need to do some extra work
  # beyond URI.parse:
  #
  #   proxy = URI.parse 'http://proxy.example'
  #   proxy.user     = 'AzureDiamond'
  #   proxy.password = 'hunter2'

  def initialize(options={})
    @name            = options[:name]            || 'PersistentHTTP'
    @idle_timeout    = options[:idle_timeout]    || 10
    @logger          = options[:logger]
    @pool_timeout    = options[:pool_timeout]
    @pool_size       = options[:pool_size]       || 1
    @warn_timeout    = options[:warn_timeout]    || 0.5
    @default_path    = options[:default_path]
    @host            = options[:host]
    @port            = options[:port]
    url              = options[:url]
    if url
      url = URI.parse(url) if url.kind_of? String
      @default_path ||= url.request_uri
      @host         ||= url.host
      @port         ||= url.port
    end

    @pool = GenePool.new(:name         => name,
                         :pool_size    => @pool_size,
                         :timeout      => @pool_timeout,
                         :warn_timeout => @warn_timeout,
                         :idle_timeout => @idle_timeout,
                         :close_proc   => :finish,
                         :logger       => @logger) do
      @logger.debug { "#{name}: Creating connection" } if @logger
      Connection.new(options)
    end
  end

  # Reset the size of the connection pool
  def pool_size=(pool_size)
    @pool.pool_size = pool_size
  end

  # Return the size of the connection pool
  def pool_size
    @pool.pool_size
  end

  ##
  # Makes a request per +req+.  If +req+ is nil a Net::HTTP::Get is performed
  # against +default_path+.
  #
  # If a block is passed #request behaves like Net::HTTP#request (the body of
  # the response will not have been read).
  #
  # +req+ must be a Net::HTTPRequest subclass (see Net::HTTP for a list).
  #
  # If there is an error and the request is idempontent according to RFC 2616
  # it will be retried automatically.

  def request(req = nil, options = {}, &block)
    @pool.with_connection do |connection|
      begin
        connection.request req, options, &block
      rescue Exception => e
        @pool.remove(connection)
        raise
      end
    end
  end

  ##
  # Shuts down all connections.
  def shutdown(timeout=10)
    @pool.close(timeout)
  end
end
