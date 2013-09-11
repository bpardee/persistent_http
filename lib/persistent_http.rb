require 'net/http'
require 'net/https'
require 'persistent_http/faster'
require 'uri'
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
  # The version of PersistentHTTP use are using
  VERSION = '1.0.0'

  ##
  # Error class for errors raised by PersistentHTTP.  Various
  # SystemCallErrors are re-raised with a human-readable message under this
  # class.
  class Error < StandardError; end

  ##
  # An SSL certificate authority.  Setting this will set verify_mode to
  # VERIFY_PEER.
  attr_accessor :ca_file

  ##
  # This client's OpenSSL::X509::Certificate
  attr_accessor :certificate

  ##
  # Sends debug_output to this IO via Net::HTTP#set_debug_output.
  #
  # Never use this method in production code, it causes a serious security
  # hole.
  attr_accessor :debug_output

  ##
  # Default path for the request
  attr_accessor :default_path
  
  ##
  # Retry even for non-idempotent (POST) requests.
  attr_accessor :force_retry

  ##
  # Headers that are added to every request
  attr_accessor :headers

  ##
  # Host for the Net:HTTP connection
  attr_reader :host
  
  ##
  # HTTP version to enable version specific features.
  attr_reader :http_version

  ##
  # Connection will be renewed if it hasn't been used in this amount of time.  Defaults to 10 seconds.
  attr_reader :idle_timeout

  ##
  # The value sent in the Keep-Alive header.  Defaults to 30.  Not needed for
  # HTTP/1.1 servers.
  #
  # This may not work correctly for HTTP/1.0 servers
  #
  # This method may be removed in a future version as RFC 2616 does not
  # require this header.
  attr_accessor :keep_alive

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
  # Seconds to wait until a connection is opened.  See Net::HTTP#open_timeout
  attr_accessor :open_timeout

  ##
  # The maximum size of the connection pool
  attr_reader :pool_size

  ##
  # Port for the Net:HTTP connection
  attr_reader :port
  
  ##
  # This client's SSL private key
  attr_accessor :private_key

  ##
  # The URL through which requests will be proxied
  attr_reader :proxy_uri

  ##
  # Seconds to wait until reading one block.  See Net::HTTP#read_timeout
  attr_accessor :read_timeout

  ##
  # Use ssl if set
  attr_reader :use_ssl
  
  ##
  # SSL verification callback.  Used when ca_file is set.
  attr_accessor :verify_callback

  ##
  # HTTPS verify mode.  Defaults to OpenSSL::SSL::VERIFY_NONE which ignores
  # certificate problems.
  #
  # You can use +verify_mode+ to override any default values.
  attr_accessor :verify_mode

  ##
  # The threshold in seconds for checking out a connection at which a warning 
  # will be logged via the logger
  attr_reader :warn_timeout

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
    @ca_file         = options[:ca_file]
    @certificate     = options[:certificate]
    @debug_output    = options[:debug_output]
    @default_path    = options[:default_path]
    @force_retry     = options[:force_retry]
    @headers         = options[:header]          || {}
    @host            = options[:host]
    @idle_timeout    = options[:idle_timeout]    || 10
    @keep_alive      = options[:keep_alive]      || 30
    @logger          = options[:logger]
    @pool_timeout    = options[:pool_timeout]
    @open_timeout    = options[:open_timeout]
    @pool_size       = options[:pool_size]       || 1
    @port            = options[:port]
    @private_key     = options[:private_key]
    @read_timeout    = options[:read_timeout]
    @use_ssl         = options[:use_ssl]
    @verify_callback = options[:verify_callback]
    @verify_mode     = options[:verify_mode]
    @warn_timeout    = options[:warn_timeout]    || 0.5
    
    url              = options[:url]
    if url
      url = URI.parse(url) if url.kind_of? String
      @default_path ||= url.request_uri
      @host         ||= url.host
      @port         ||= url.port
      @use_ssl      ||= url.scheme == 'https'          
    end
    
    @port ||= (@use_ssl ? 443 : 80)

    # Hash containing the request counts based on the connection
    @count_hash = Hash.new(0)

    raise 'host not set' unless @host
    net_http_args = [@host, @port]
    connection_id = net_http_args.join ':'

    proxy = options[:proxy]

    @proxy_uri = case proxy
                 when :ENV      then proxy_from_env
                 when URI::HTTP then proxy
                 when nil       then # ignore
                 else raise ArgumentError, 'proxy must be :ENV or a URI::HTTP'
                 end

    if @proxy_uri then
      @proxy_args = [
        @proxy_uri.host,
        @proxy_uri.port,
        @proxy_uri.user,
        @proxy_uri.password,
      ]

      @proxy_connection_id = [nil, *@proxy_args].join ':'

      connection_id << @proxy_connection_id
      net_http_args.concat @proxy_args
    end

    @pool = GenePool.new(:name         => name + '-' + connection_id,
                         :pool_size    => @pool_size,
                         :timeout      => @pool_timeout,
                         :warn_timeout => @warn_timeout,
                         :idle_timeout => @idle_timeout,
                         :close_proc   => nil,
                         :logger       => @logger) do
      begin
        @logger.debug { "#{name}: Creating connection" } if @logger
        connection = Net::HTTP.new(*net_http_args)
        connection.set_debug_output @debug_output if @debug_output
        connection.open_timeout = @open_timeout if @open_timeout
        connection.read_timeout = @read_timeout if @read_timeout

        ssl connection if @use_ssl

        connection.start
        @logger.debug { "#{name} #{connection}: Connection created" } if @logger
        connection
      rescue Errno::ECONNREFUSED
        raise Error, "connection refused: #{connection.address}:#{connection.port}"
      rescue Errno::EHOSTDOWN
        raise Error, "host down: #{connection.address}:#{connection.port}"
      end
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
    retried      = false
    bad_response = false

    req = Net::HTTP::Get.new @default_path unless req

    headers.each do |pair|
      req.add_field(*pair)
    end

    req.add_field 'Connection', 'keep-alive'
    req.add_field 'Keep-Alive', @keep_alive

    @pool.with_connection do |connection|
      begin
        options.each do |key, value|
          connection.send("#{key}=", value)
        end
        response = connection.request req, &block
        @http_version ||= response.http_version
        @count_hash[connection.object_id] += 1
        return response

      rescue Timeout::Error => e
        due_to = "(due to #{e.message} - #{e.class})"
        message = error_message connection
        @logger.info "#{name}: Removing connection #{due_to} #{message}" if @logger
        remove connection
        raise
        
      rescue Net::HTTPBadResponse => e
        message = error_message connection
        if bad_response or not (idempotent? req or @force_retry)
          @logger.info "#{name}: Removing connection because of too many bad responses #{message}" if @logger
          remove connection
          raise Error, "too many bad responses #{message}"
        else
          bad_response = true
          @logger.info "#{name}: Renewing connection because of bad response #{message}" if @logger
          connection = renew connection
          retry
        end

      rescue IOError, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EPIPE => e
        due_to = "(due to #{e.message} - #{e.class})"
        message = error_message connection
        if retried or not (idempotent? req or @force_retry)
          @logger.info "#{name}: Removing connection #{due_to} #{message}" if @logger
          remove connection
          raise Error, "too many connection resets #{due_to} #{message}"
        else
          retried = true
          @logger.info "#{name}: Renewing connection #{due_to} #{message}" if @logger
          connection = renew connection
          retry
        end
      end
    end
  end

  ##
  # Shuts down all connections.
  def shutdown(timeout=10)
    @pool.close(timeout)
  end

  #######
  private
  #######

  ##
  # Returns an error message containing the number of requests performed on
  # this connection

  def error_message connection
    requests = @count_hash[connection.object_id] || 0
    "after #{requests} requests on #{connection.object_id}"
  end

  ##
  # URI::escape wrapper

  def escape str
    URI.escape str if str
  end

  ##
  # Finishes the Net::HTTP +connection+

  def finish connection
    @count_hash.delete(connection.object_id)
    connection.finish
  rescue IOError
  end

  ##
  # Is +req+ idempotent according to RFC 2616?

  def idempotent? req
    case req
    when Net::HTTP::Delete, Net::HTTP::Get, Net::HTTP::Head,
         Net::HTTP::Options, Net::HTTP::Put, Net::HTTP::Trace then
      true
    end
  end

  ##
  # Adds "http://" to the String +uri+ if it is missing.

  def normalize_uri uri
    (uri =~ /^https?:/) ? uri : "http://#{uri}"
  end

  ##
  # Creates a URI for an HTTP proxy server from ENV variables.
  #
  # If +HTTP_PROXY+ is set a proxy will be returned.
  #
  # If +HTTP_PROXY_USER+ or +HTTP_PROXY_PASS+ are set the URI is given the
  # indicated user and password unless HTTP_PROXY contains either of these in
  # the URI.
  #
  # For Windows users lowercase ENV variables are preferred over uppercase ENV
  # variables.

  def proxy_from_env
    env_proxy = ENV['http_proxy'] || ENV['HTTP_PROXY']

    return nil if env_proxy.nil? or env_proxy.empty?

    uri = URI.parse(normalize_uri(env_proxy))

    unless uri.user or uri.password then
      uri.user     = escape ENV['http_proxy_user'] || ENV['HTTP_PROXY_USER']
      uri.password = escape ENV['http_proxy_pass'] || ENV['HTTP_PROXY_PASS']
    end

    uri
  end

  ##
  # Finishes then removes the Net::HTTP +connection+

  def remove connection
    finish connection
    @pool.remove(connection)
  end

  ##
  # Finishes then renews the Net::HTTP +connection+.  It may be unnecessary 
  # to completely recreate the connection but connections that get timed out
  # in JRuby leave the ssl context in a frozen object state.

  def renew connection
    finish connection
    connection = @pool.renew(connection)
  end

  ##
  # Enables SSL on +connection+

  def ssl connection
    connection.use_ssl = true

    # suppress warning but allow override
    connection.verify_mode = OpenSSL::SSL::VERIFY_NONE unless @verify_mode

    if @ca_file then
      connection.ca_file = @ca_file
      connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
      connection.verify_callback = @verify_callback if @verify_callback
    end

    if @certificate and @private_key then
      connection.cert = @certificate
      connection.key  = @private_key
    end

    connection.verify_mode = @verify_mode if @verify_mode
  end
  
end

