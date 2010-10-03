require 'rubygems'
require 'test/unit'
require 'shoulda'
require 'persistent_http'
require 'openssl'
require 'stringio'
require 'logger'

CMD_SUCCESS      = 'success'
CMD_SLEEP        = 'sleep'
CMD_BAD_RESPONSE = 'bad_response'
CMD_EOF_ERROR    = 'eof_error'
CMD_CONNRESET    = 'connreset'
CMD_ECHO         = 'echo'

PASS = 'pass'
FAIL = 'fail'

DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN    = 9000
DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED = 9001

$debug = false
$count = -1

class Net::HTTP
  def connect
    raise Errno::EHOSTDOWN    if open_timeout == DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN
    raise Errno::ECONNREFUSED if open_timeout == DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED
  end

  def successful_response
    r = Net::HTTPResponse.allocate
    def r.http_version() '1.1'; end
    def r.read_body() :read_body; end
    yield r if block_given?
    r
  end

  def request(req, &block)
    $count += 1
    puts "path=#{req.path} count=#{$count}" if $debug
    args = req.path[1..-1].split('/')
    cmd = args.shift
    i = $count % args.size if args.size > 0
    puts "i=#{i}" if $debug
    if cmd == CMD_ECHO
      res = successful_response(&block)
      eval "def res.body() \"#{req.body}\" end"
      return res
    elsif cmd == CMD_SUCCESS || args[i] == PASS
      return successful_response(&block)
    end
    case cmd
    when CMD_SLEEP
      sleep args[i].to_i
      return successful_response(&block)
    when CMD_BAD_RESPONSE
      raise Net::HTTPBadResponse.new('Dummy bad response') 
    when CMD_EOF_ERROR
      raise EOFError.new('Dummy EOF error') 
    when CMD_CONNRESET
      raise Errno::ECONNRESET
    else
      return successful_response(&block)
    end 
  end
end

class PersistentHTTP
  attr_reader :pool

  # Make private methods public
  send(:public, *(self.private_instance_methods - Object.private_instance_methods))
end

class PersistentHTTPTest < Test::Unit::TestCase

  def clear_proxy_env
    ENV.delete 'http_proxy'
    ENV.delete 'HTTP_PROXY'
    ENV.delete 'http_proxy_user'
    ENV.delete 'HTTP_PROXY_USER'
    ENV.delete 'http_proxy_pass'
    ENV.delete 'HTTP_PROXY_PASS'
  end

  def uri_for(*args)
    '/' + args.join('/')
  end

  def get_request(*args)
    puts "uri=#{uri_for(args)}" if $debug
    $count = -1
    return Net::HTTP::Get.new(uri_for(args))
  end
  
  def post_request(*args)
    puts "uri=#{uri_for(args)}" if $debug
    $count = -1
    return Net::HTTP::Post.new(uri_for(args))
  end

  def http_and_io(options={})
    io = StringIO.new
    logger = Logger.new(io)
    logger.level = Logger::INFO
    default_options = {:name => 'TestNetHTTPPersistent', :logger => logger, :pool_size => 1}
    http = PersistentHTTP.new(default_options.merge(options))
    [http, io]
  end

  context 'simple setup' do
    setup do
      @io = StringIO.new
      logger = Logger.new(@io)
      logger.level = Logger::INFO
      @http = PersistentHTTP.new(:host => 'example.com', :name => 'TestNetHTTPPersistent', :logger => logger)
      @http.headers['user-agent'] = 'test ua'
    end

    should 'have options set' do
      assert_equal @http.proxy_uri, nil
      assert_equal 'TestNetHTTPPersistent', @http.name
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
      c = Object.new
      def c.finish; @finished = true end
      def c.finished?; @finished end
      def c.start; @started = true end
      def c.started?; @started end

      @http.finish c

      assert !c.started?
      assert c.finished?
    end

    should 'handle finish io error' do
      c = Object.new
      def c.finish; @finished = true; raise IOError end
      def c.finished?; @finished end
      def c.start; @started = true end
      def c.started?; @started end

      @http.finish c

      assert !c.started?
      assert c.finished?
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

    should 'allow ssl' do
      @http.verify_callback = :callback
      c = Net::HTTP.new('localhost', 80)
    
      @http.ssl c
    
      assert c.use_ssl?
      assert_equal OpenSSL::SSL::VERIFY_NONE, c.verify_mode
      assert_nil c.verify_callback
    end
    
    should 'allow ssl ca_file' do
      @http.ca_file = 'ca_file'
      @http.verify_callback = :callback
      c = Net::HTTP.new('localhost', 80)
    
      @http.ssl c
    
      assert c.use_ssl?
      assert_equal OpenSSL::SSL::VERIFY_PEER, c.verify_mode
      assert_equal :callback, c.verify_callback
    end
    
    should 'allow ssl certificate' do
      @http.certificate = :cert
      @http.private_key = :key
      c = Net::HTTP.new('localhost', 80)
    
      @http.ssl c
    
      assert c.use_ssl?
      assert_equal :cert, c.cert
      assert_equal :key,  c.key
    end
    
    should 'allow ssl verify_mode' do
      @http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      c = Net::HTTP.new('localhost', 80)
    
      @http.ssl c
    
      assert c.use_ssl?
      assert_equal OpenSSL::SSL::VERIFY_NONE, c.verify_mode
    end
  end

  context 'initialize proxy by env' do
    setup do
      clear_proxy_env
      ENV['HTTP_PROXY'] = 'proxy.example'
      @http = PersistentHTTP.new(:host => 'foobar', :proxy => :ENV)
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
      @http               = PersistentHTTP.new(:url => 'https://zulu.com/foobar', :proxy => @proxy_uri)
    end

    should 'match proxy_uri and have proxy connection' do
      assert_equal @proxy_uri, @http.proxy_uri
      assert_equal true, @http.use_ssl
      assert_equal 'zulu.com', @http.host
      assert_equal '/foobar', @http.default_path

      @http.pool.with_connection do |c|
        assert c.started?
        assert c.proxy?
      end
    end
  end

  context 'initialize proxy by env' do
    setup do
      clear_proxy_env
      ENV['HTTP_PROXY']      = 'proxy.example'
      ENV['HTTP_PROXY_USER'] = 'johndoe'
      ENV['HTTP_PROXY_PASS'] = 'muffins'
      @http                  = PersistentHTTP.new(:url => 'https://zulu.com/foobar', :proxy => :ENV)
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
      @http                  = PersistentHTTP.new(:url => 'https://zulu.com/foobar', :proxy => :ENV)
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
      @http = PersistentHTTP.new(:url => 'http://example.com')
      @http.open_timeout = 123
      @http.read_timeout = 321
    end

    should 'have timeouts set' do
      @http.pool.with_connection do |c|
        assert c.started?
        assert !c.proxy?

        assert_equal 123, c.open_timeout
        assert_equal 321, c.read_timeout

        assert_equal 'example.com', c.address
        assert_equal 80, c.port
        assert !@http.use_ssl
      end
    end

    should 'reuse same connection' do
      c1, c2 = nil, nil
      @http.pool.with_connection do |c|
        c1 = c
        assert c.started?
      end
      @http.pool.with_connection do |c|
        c2 = c
        assert c.started?
      end
      assert_same c1,c2
    end
  end

  context 'with debug_output' do
    setup do
      @io = StringIO.new
      @http = PersistentHTTP.new(:url => 'http://example.com', :debug_output => @io)
    end

    should 'have debug_output set' do
      @http.pool.with_connection do |c|
        assert c.started?
        assert_equal @io, c.instance_variable_get(:@debug_output)
        assert_equal 'example.com', c.address
        assert_equal 80, c.port
      end
    end
  end

  context 'with host down' do
    setup do 
      @http = PersistentHTTP.new(:url => 'http://example.com', :open_timeout => DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN)
    end

    should 'assert error' do
      e = assert_raises PersistentHTTP::Error do
        @http.request(get_request(CMD_SUCCESS))
      end
      assert_match %r%host down%, e.message
    end
  end

  context 'with connection refused' do
    setup do
      @http = PersistentHTTP.new(:url => 'http://example.com', :open_timeout => DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED)
    end

    should 'assert error' do
      e = assert_raises PersistentHTTP::Error do
        @http.request(get_request(CMD_SUCCESS))
      end
      assert_match %r%connection refused%, e.message
    end
  end
  
  context 'with pool size of 3' do
    setup do
      @http = PersistentHTTP.new(:url => 'http://example.com', :pool_size => 3)
    end
    
    should 'only allow 3 connections checked out at a time' do
      @http.request(get_request(CMD_SUCCESS))
      pool = @http.pool
      2.times do
        conns = []
        pool.with_connection do |c1|
          pool.with_connection do |c2|
            conns << c2
            pool.with_connection do |c3|
              conns << c3
              begin
                Timeout.timeout(2) do
                  pool.with_connection { |c4| }
                  assert false, 'should NOT have been able to get 4th connection'
                end
              rescue  Timeout::Error => e
                # successfully failed to get a connection
              end
              @http.remove(c1)
              Timeout.timeout(1) do
                begin
                  pool.with_connection do |c4|
                    conns << c4
                  end
                rescue  Timeout::Error => e
                  assert false, 'should have been able to get 4th connection'
                end
              end
            end
          end
        end
        pool.with_connection do |c1|
          pool.with_connection do |c2|
            pool.with_connection do |c3|
              assert_equal conns, [c1,c2,c3]
            end
          end
        end
        # Do it a 2nd time with finish returning an IOError
        c1 = conns[0]
        def c1.finish
          super
          raise IOError
        end
      end
    end

    should 'handle renew' do
      @http.request(get_request(CMD_SUCCESS))
      pool = @http.pool
      2.times do
        conns = []
        pool.with_connection do |c1|
          pool.with_connection do |c2|
            conns << c2
            pool.with_connection do |c3|
              conns << c3
              new_c1 = @http.renew(c1)
              assert c1 != new_c1
              conns.unshift(new_c1)
            end
          end
        end
        pool.with_connection do |c1|
          pool.with_connection do |c2|
            pool.with_connection do |c3|
              assert_equal conns, [c1,c2,c3]
            end
          end
        end
        # Do it a 2nd time with finish returning an IOError
        c1 = conns[0]
        def c1.finish
          super
          raise IOError
        end
      end
    end

    should 'handle renew with exception' do
      pool = @http.pool
      [[DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN, %r%host down%], [DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED, %r%connection refused%]].each do |pair|
        dummy_open_timeout = pair.first
        error_message = pair.last
        pool.with_connection do |c|
          old_c = c
          @http.open_timeout = dummy_open_timeout
          e = assert_raises PersistentHTTP::Error do
            new_c = @http.renew c
          end
          assert_match error_message, e.message

          # Make sure our pool is still in good shape
          @http.open_timeout = 5   # Any valid timeout will do
          pool.with_connection do |c1|
            assert old_c != c1
            pool.with_connection do |c2|
              assert old_c != c2
            end
          end
        end
      end
    end
  end
#   
#   # def test_shutdown
#   #   c = connection
#   #   cs = conns
#   #   rs = reqs
#   # 
#   #   orig = @http
#   #   @http = PersistentHTTP.new 'name'
#   #   c2 = connection
#   # 
#   #   orig.shutdown
#   # 
#   #   assert c.finished?
#   #   refute c2.finished?
#   # 
#   #   refute_same cs, conns
#   #   refute_same rs, reqs
#   # end
#   # 
#   # def test_shutdown_not_started
#   #   c = Object.new
#   #   def c.finish() raise IOError end
#   # 
#   #   conns["#{@uri.host}:#{@uri.port}"] = c
#   # 
#   #   @http.shutdown
#   # 
#   #   assert_nil Thread.current[@http.connection_key]
#   #   assert_nil Thread.current[@http.request_key]
#   # end
#   # 
#   # def test_shutdown_no_connections
#   #   @http.shutdown
#   # 
#   #   assert_nil Thread.current[@http.connection_key]
#   #   assert_nil Thread.current[@http.request_key]
#   # end
#   
end

