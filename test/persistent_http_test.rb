require 'test_helper'

class PersistentHTTP
  attr_reader :pool
end

class PersistentHTTPTest < Test::Unit::TestCase

  context PersistentHTTP do
    setup do
      @io = StringIO.new
      logger = Logger.new(@io)
      logger.level = Logger::INFO
      @http = PersistentHTTP.new(:host => 'example.com', :name => 'TestNetHTTPPersistent', :logger => logger)
    end

    should 'return the default pool_size' do
      assert_equal 1, @http.pool_size
      assert_equal 1, @http.pool.pool_size
    end

    should 'allow you to change the pool_size' do
      @http.pool_size = 4
      assert_equal 4, @http.pool_size
      assert_equal 4, @http.pool.pool_size
    end

    should 'allow you to shutdown the pool' do
      @http.shutdown
      assert_equal 0, @http.pool.size
    end

    should 'have options set' do
      assert_equal 'TestNetHTTPPersistent', @http.name
    end
  end

  context 'with timeouts set' do
    setup do
      @http = PersistentHTTP.new(:url => 'http://example.com')
    end

    should 'reuse same connection' do
      c1, c2 = nil, nil
      @http.pool.with_connection do |c|
        c1 = c
        assert c.connection.started?
      end
      @http.pool.with_connection do |c|
        c2 = c
        assert c.connection.started?
      end
      assert_same c1,c2
    end
  end

  context 'with pool size of 3' do
    setup do
      @http = PersistentHTTP.new(:url => 'http://example.com', :pool_size => 3)
    end

    should 'return the correct pool size' do
      assert_equal 3, @http.pool_size
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
              pool.remove(c1)
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

    should 'handle renew with exception' do
      pool = @http.pool
      [[DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN, %r%host down%], [DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED, %r%connection refused%]].each do |pair|
        dummy_open_timeout = pair.first
        error_message = pair.last
        pool.with_connection do |c|
          old_c = c
          Net::HTTP.global_open_timeout = dummy_open_timeout
          e = assert_raises PersistentHTTP::Error do
            res = c.request(get_request(CMD_EOF_ERROR, FAIL))
          end
          assert_match error_message, e.message

          # Make sure our pool is still in good shape
          Net::HTTP.global_open_timeout = 5 # Any valid timeout will do
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

  context 'with pool_timeout of 1' do
    setup do
      @pool_size = 2
      @pool_timeout = 1
      @http = PersistentHTTP.new(:url => 'http://example.com', :pool_size => @pool_size, :pool_timeout => @pool_timeout)
    end

    should 'return the correct pool size' do
      assert_equal @pool_size, @http.pool_size
    end

    should 'raise a Timeout::Error when unable to acquire connection' do
      2.times do
        @pool_size.times do
          Thread.new do
            res = @http.request(get_request(CMD_SLEEP, @pool_timeout + 1))
            assert res.kind_of?(Net::HTTPResponse)
          end
        end
      end
      sleep(0.1)
      start_time = Time.now
      assert_raises Timeout::Error do
        res = @http.request(get_request(CMD_SUCCESS))
        puts "No timeout after #{Time.now - start_time} seconds"
      end
      # Let the threads complete so we can do it again
      sleep 2
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
