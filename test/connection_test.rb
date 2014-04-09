require 'test_helper'

class ConnectionTest < Test::Unit::TestCase

  context PersistentHTTP::Connection do
    setup do
      @io = StringIO.new
      @logger = Logger.new(@io)
      @logger.level = Logger::INFO
    end

    context 'simple setup' do
      setup do
        @http = PersistentHTTP::Connection.new(:host => 'localhost', :name => 'TestNetHTTPPersistent::Connection', :logger => @logger)
        @http.headers['user-agent'] = 'test ua'
      end

      should 'have options set' do
        assert_equal @http.proxy_uri, nil
        assert @http.name.start_with?('TestNetHTTPPersistent::Connection'), @http.name
      end

      should 'handle escape' do
        assert_equal nil,  @http.escape(nil)
        assert_equal '%20', @http.escape(' ')
      end

      should 'handle error' do
        req = get_request CMD_EOF_ERROR, PASS, PASS, PASS, PASS, FAIL, PASS, PASS
        6.times do
          @http.request(req)
        end
        assert_match "after 4 requests on", @io.string
      end

      should 'handle finish' do
        @http.finish
        c = @http.connection
        assert c.finish_called
      end

      should 'handle finish io error' do
        c = @http.connection
        c.io_error_on_finish = true
        @http.finish
        assert c.finish_called
      end

      should 'fill in http version' do
        assert_nil @http.http_version
        @http.request(get_request(CMD_SUCCESS))
        assert_equal '1.1', @http.http_version
      end

      should 'handle idempotent' do
        assert @http.idempotent? Net::HTTP::Delete.new '/'
        assert @http.idempotent? Net::HTTP::Get.new '/'
        assert @http.idempotent? Net::HTTP::Head.new '/'
        assert @http.idempotent? Net::HTTP::Options.new '/'
        assert @http.idempotent? Net::HTTP::Put.new '/'
        assert @http.idempotent? Net::HTTP::Trace.new '/'

        assert !@http.idempotent?(Net::HTTP::Post.new '/')
      end

      should 'handle normalize_uri' do
        assert_equal 'http://example',  @http.normalize_uri('example')
        assert_equal 'http://example',  @http.normalize_uri('http://example')
        assert_equal 'https://example', @http.normalize_uri('https://example')
      end

      should 'handle simple request' do
        req = get_request(CMD_SUCCESS)
        res = @http.request(req)

        assert_kind_of Net::HTTPResponse, res

        assert_kind_of Net::HTTP::Get, req
        assert_equal uri_for(CMD_SUCCESS), req.path
        assert_equal 'keep-alive',         req['connection']
        assert_equal '30',                 req['keep-alive']
        assert_match %r%test ua%,          req['user-agent']
      end

      should 'handle request with block' do
        body = nil

        req = get_request(CMD_SUCCESS)
        res = @http.request(req) do |r|
          body = r.read_body
        end

        assert_kind_of Net::HTTPResponse, res
        assert !body.nil?

        assert_kind_of Net::HTTP::Get, req
        assert_equal uri_for(CMD_SUCCESS), req.path
        assert_equal 'keep-alive',         req['connection']
        assert_equal '30',                 req['keep-alive']
        assert_match %r%test ua%,          req['user-agent']
      end

      should 'handle bad response' do
        req = get_request(CMD_BAD_RESPONSE, FAIL, FAIL)
        e = assert_raises PersistentHTTP::Error do
          @http.request req
        end
        assert_match %r%too many bad responses%, e.message
        assert_match %r%Renewing connection because of bad response%, @io.string
        assert_match %r%Removing connection because of too many bad responses%, @io.string

        res = @http.request(get_request(CMD_SUCCESS))
        assert_kind_of Net::HTTPResponse, res
      end

      should 'handle connection reset' do
        req = get_request(CMD_CONNRESET, FAIL, FAIL)
        e = assert_raises PersistentHTTP::Error do
          @http.request req
        end

        assert_match %r%too many connection resets%, e.message
        assert_match %r%Renewing connection %, @io.string
        assert_match %r%Removing connection %, @io.string

        res = @http.request(get_request(CMD_SUCCESS))
        assert_kind_of Net::HTTPResponse, res
      end

      should 'retry on bad response' do
        res = @http.request(get_request(CMD_BAD_RESPONSE, FAIL, PASS))
        assert_match %r%Renewing connection because of bad response%, @io.string
        assert_kind_of Net::HTTPResponse, res
      end

      should 'retry on connection reset' do
        res = @http.request(get_request(CMD_CONNRESET, FAIL, PASS))
        assert_match %r%Renewing connection %, @io.string
        assert_kind_of Net::HTTPResponse, res
      end

      should 'not retry on bad response from post' do
        post = post_request(CMD_BAD_RESPONSE, FAIL, PASS)
        e = assert_raises PersistentHTTP::Error do
          @http.request(post)
        end
        assert_match %r%too many bad responses%, e.message
        assert_match %r%Removing connection because of too many bad responses%, @io.string

        res = @http.request(get_request(CMD_SUCCESS))
        assert_kind_of Net::HTTPResponse, res
      end

      should 'not retry on connection reset from post' do
        post = post_request(CMD_CONNRESET, FAIL, PASS)
        e = assert_raises PersistentHTTP::Error do
          @http.request(post)
        end
        assert_match %r%too many connection resets%, e.message
        assert_match %r%Removing connection %, @io.string

        res = @http.request(get_request(CMD_SUCCESS))
        assert_kind_of Net::HTTPResponse, res
      end

      should 'retry on bad response from post when force_retry set' do
        @http.force_retry = true
        post = post_request(CMD_BAD_RESPONSE, FAIL, PASS)
        res = @http.request post
        assert_match %r%Renewing connection because of bad response%, @io.string
        assert_kind_of Net::HTTPResponse, res
      end

      should 'retry on connection reset from post when force_retry set' do
        @http.force_retry = true
        post = post_request(CMD_CONNRESET, FAIL, PASS)
        res = @http.request post
        assert_match %r%Renewing connection %, @io.string
        assert_kind_of Net::HTTPResponse, res
      end

      should 'allow post' do
        post = Net::HTTP::Post.new(uri_for CMD_ECHO)
        post.body = 'hello PersistentHTTP'
        res = @http.request(post)
        assert_kind_of Net::HTTPResponse, res
        assert_equal post.body, res.body
      end
    end

    context 'with ssl' do
      should 'allow ssl' do
        @http = PersistentHTTP::Connection.new(:url => 'https://localhost')
        c = @http.connection
        assert c.use_ssl?
        assert_equal OpenSSL::SSL::VERIFY_NONE, c.verify_mode
        assert_nil c.verify_callback
      end

      should 'allow ssl ca_file' do
        @http = PersistentHTTP::Connection.new(:url => 'https://localhost', :ca_file => 'ca_file', :verify_callback => :callback)
        c = @http.connection
        assert c.use_ssl?
        assert_equal OpenSSL::SSL::VERIFY_PEER, c.verify_mode
        assert_equal :callback, c.verify_callback
        assert_equal 'ca_file', c.ca_file
      end

      should 'allow ssl certificate' do
        @http = PersistentHTTP::Connection.new(:url => 'https://localhost', :certificate => :cert, :private_key => :key)
        c = @http.connection
        assert c.use_ssl?
        assert_equal :cert, c.cert
        assert_equal :key,  c.key
      end

      should 'allow ssl verify_mode' do
        @http = PersistentHTTP::Connection.new(:url => 'https://localhost', :verify_mode => OpenSSL::SSL::VERIFY_NONE)
        c = @http.connection
        assert c.use_ssl?
        assert_equal OpenSSL::SSL::VERIFY_NONE, c.verify_mode
      end
    end

    context 'initialize proxy by env' do
      setup do
        clear_proxy_env
        ENV['HTTP_PROXY'] = 'proxy.example'
        @http = PersistentHTTP::Connection.new(:host => 'foobar', :proxy => :ENV)
      end

      teardown do
        clear_proxy_env
      end

      should 'match HTTP_PROXY' do
        assert_equal URI.parse('http://proxy.example'), @http.proxy_uri
        assert_equal 'foobar', @http.host
      end
    end

    context 'initialize proxy by uri' do
      setup do
        @proxy_uri          = URI.parse 'http://proxy.example'
        @proxy_uri.user     = 'johndoe'
        @proxy_uri.password = 'muffins'
        @http               = PersistentHTTP::Connection.new(:url => 'https://zulu.com/foobar', :proxy => @proxy_uri)
      end

      should 'match proxy_uri and have proxy connection' do
        assert_equal @proxy_uri, @http.proxy_uri
        assert_equal true, @http.use_ssl
        assert_equal 'zulu.com', @http.host
        assert_equal '/foobar', @http.default_path

        c = @http.connection
        assert c.started?
        assert c.proxy?
      end
    end

    context 'initialize proxy by env' do
      setup do
        clear_proxy_env
        ENV['HTTP_PROXY']      = 'proxy.example'
        ENV['HTTP_PROXY_USER'] = 'johndoe'
        ENV['HTTP_PROXY_PASS'] = 'muffins'
        @http                  = PersistentHTTP::Connection.new(:url => 'https://zulu.com/foobar', :proxy => :ENV)
      end

      teardown do
        clear_proxy_env
      end

      should 'create proxy_uri from env' do
        expected          = URI.parse 'http://proxy.example'
        expected.user     = 'johndoe'
        expected.password = 'muffins'

        assert_equal expected, @http.proxy_uri
      end
    end

    context 'initialize proxy by env lower' do
      setup do
        clear_proxy_env
        ENV['http_proxy']      = 'proxy.example'
        ENV['http_proxy_user'] = 'johndoe'
        ENV['http_proxy_pass'] = 'muffins'
        @http                  = PersistentHTTP::Connection.new(:url => 'https://zulu.com/foobar', :proxy => :ENV)
      end

      teardown do
        clear_proxy_env
      end

      should 'create proxy_uri from env' do
        expected          = URI.parse 'http://proxy.example'
        expected.user     = 'johndoe'
        expected.password = 'muffins'

        assert_equal expected, @http.proxy_uri
      end
    end

    context 'with timeouts set' do
      setup do
        @http = PersistentHTTP::Connection.new(:url => 'http://example.com', :open_timeout => 123, :read_timeout => 321)
      end

      should 'have timeouts set' do
        c = @http.connection
        assert c.started?
        assert !c.proxy?

        assert_equal 123, c.open_timeout
        assert_equal 321, c.read_timeout

        assert_equal 'example.com', c.address
        assert_equal 80, c.port
        assert !@http.use_ssl
      end
    end

    context 'with debug_output' do
      setup do
        @io = StringIO.new
        @http = PersistentHTTP::Connection.new(:url => 'http://example.com', :debug_output => @io)
      end

      should 'have debug_output set' do
        c = @http.connection
        assert c.started?
        assert_equal @io, c.instance_variable_get(:@debug_output)
        assert_equal 'example.com', c.address
        assert_equal 80, c.port
      end
    end

    context 'with host down' do
      should 'assert error' do
        e = assert_raises PersistentHTTP::Error do
          PersistentHTTP::Connection.new(:url => 'http://example.com', :open_timeout => DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN)
        end
        assert_match %r%host down%, e.message
      end
    end

    context 'with connection refused' do
      should 'assert error' do
        e = assert_raises PersistentHTTP::Error do
          PersistentHTTP::Connection.new(:url => 'http://example.com', :open_timeout => DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED)
        end
        assert_match %r%connection refused%, e.message
      end
    end
  end
end
