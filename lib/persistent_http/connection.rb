require 'net/http'
require 'net/https'
require 'uri'

##
# Simplified frontend for Net::HTTP
#
# Example:
#
#   @http = PersistentHTTP::Connection.new(
#     :logger       => Rails.logger,
#     :force_retry  => true,
#     :url          => 'https://www.example.com/echo/foo'  # equivalent to :use_ssl => true, :host => 'www.example.com', :default_path => '/echo/foo'
#   )
#
#   def send_get_message
#     response = @http.request
#     ... Handle response as you would a normal Net::HTTPResponse ...
#   end
#
#   def send_post_message
#     request = Net::HTTP::Post.new('/perform_service)
#     ... Modify request as needed ...
#     response = @http.request(request)
#     ... Handle response as you would a normal Net::HTTPResponse ...
#   end

class PersistentHTTP
  class Connection

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
    # Seconds to wait until a connection is opened.  See Net::HTTP#open_timeout
    attr_accessor :open_timeout

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
    # Creates a new HTTP Connection.
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
      @name            = options[:name]            || 'PeristentHTTP::Connection'
      @ca_file         = options[:ca_file]
      @certificate     = options[:certificate]
      @debug_output    = options[:debug_output]
      @default_path    = options[:default_path]
      @force_retry     = options[:force_retry]
      @headers         = options[:header]          || {}
      @host            = options[:host]
      @keep_alive      = options[:keep_alive]      || 30
      @logger          = options[:logger]
      @port            = options[:port]
      @private_key     = options[:private_key]
      @open_timeout    = options[:open_timeout]
      @read_timeout    = options[:read_timeout]
      @use_ssl         = options[:use_ssl]
      @verify_callback = options[:verify_callback]
      @verify_mode     = options[:verify_mode]
      # Because maybe we want a non-persistent connection and are just using this for the proxy stuff
      @non_persistent  = options[:non_persistent]

      url              = options[:url]
      if url
        url = URI.parse(url) if url.kind_of? String
        @default_path ||= url.request_uri
        @host         ||= url.host
        @port         ||= url.port
        @use_ssl      ||= url.scheme == 'https'
      end

      @port ||= (@use_ssl ? 443 : 80)

      raise 'host not set' unless @host
      @net_http_args = [@host, @port]

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

        @net_http_args.concat @proxy_args
      end

      @name += ':' + @net_http_args.join(':')
      @logger.debug { "#{@name}: Creating connection" } if @logger
      renew
    end

    def renew
      finish if @connection
      @message_count = 0
      @connection = Net::HTTP.new(*@net_http_args)
      @connection.set_debug_output @debug_output if @debug_output
      @connection.open_timeout = @open_timeout if @open_timeout
      @connection.read_timeout = @read_timeout if @read_timeout

      ssl if @use_ssl

      @connection.start
      @logger.debug { "#{@name} #{@connection}: Connection created" } if @logger
    rescue Errno::ECONNREFUSED
      raise Error, "connection refused: #{@connection.address}:#{@connection.port}"
    rescue Errno::EHOSTDOWN
      raise Error, "host down: #{@connection.address}:#{@connection.port}"
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

      unless @non_persistent
        req.add_field 'Connection', 'keep-alive'
        req.add_field 'Keep-Alive', @keep_alive
      end

      begin
        options.each do |key, value|
          @connection.send("#{key}=", value)
        end
        response = @connection.request req, &block
        @http_version ||= response.http_version
        @message_count += 1
        return response

      rescue Timeout::Error => e
        due_to = "(due to #{e.message} - #{e.class})"
        @logger.info "#{@name}: Removing connection #{due_to} #{error_message}" if @logger
        finish
        raise

      rescue Net::HTTPBadResponse => e
        if bad_response or not (idempotent? req or @force_retry)
          @logger.info "#{@name}: Removing connection because of too many bad responses #{error_message}" if @logger
          finish
          raise Error, "too many bad responses #{error_message}"
        else
          bad_response = true
          @logger.info "#{@name}: Renewing connection because of bad response #{error_message}" if @logger
          renew
          retry
        end

      rescue IOError, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EPIPE => e
        due_to = "(due to #{e.message} - #{e.class})"
        if retried or not (idempotent? req or @force_retry)
          @logger.info "#{@name}: Removing connection #{due_to} #{error_message}" if @logger
          finish
          raise Error, "too many connection resets #{due_to} #{error_message}"
        else
          retried = true
          @logger.info "#{@name}: Renewing connection #{due_to} #{error_message}" if @logger
          renew
          retry
        end
      end
    end

    ##
    # Finishes the Net::HTTP +connection+

    def finish
      @connection.finish
    rescue IOError
    end

    def to_s
      @name
    end

    #######
    private
    #######

    ##
    # Returns an error message containing the number of requests performed on
    # this connection

    def error_message
      "after #{@message_count} requests on #{@connection.object_id}"
    end

    ##
    # URI::escape wrapper

    def escape str
      URI.escape str if str
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
    # Enables SSL on +connection+

    def ssl
      @connection.use_ssl = true

      # suppress warning but allow override
      @connection.verify_mode = OpenSSL::SSL::VERIFY_NONE unless @verify_mode

      if @ca_file then
        @connection.ca_file = @ca_file
        @connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
        @connection.verify_callback = @verify_callback if @verify_callback
      end

      if @certificate and @private_key then
        @connection.cert = @certificate
        @connection.key  = @private_key
      end

      @connection.verify_mode = @verify_mode if @verify_mode
    end
  end
end
