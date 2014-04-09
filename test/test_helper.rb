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
  attr_reader :finish_called
  attr_accessor :io_error_on_finish

  @@global_open_timeout = 5

  def self.global_open_timeout=(open_timeout)
    @@global_open_timeout = open_timeout
  end

  def connect
    raise Errno::EHOSTDOWN    if open_timeout == DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN || @@global_open_timeout == DUMMY_OPEN_TIMEOUT_FOR_HOSTDOWN
    raise Errno::ECONNREFUSED if open_timeout == DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED || @@global_open_timeout == DUMMY_OPEN_TIMEOUT_FOR_CONNREFUSED
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

  def finish
    @finish_called = true
    raise IOError if @io_error_on_finish
  end
end

class PersistentHTTP
  class Connection
    attr_reader :connection
    # Make private methods public
    send(:public, *(self.private_instance_methods - Object.private_instance_methods))
  end
end

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
  default_options = {:name => 'TestNetHTTPPersistent::Connection', :logger => logger}
  http = PersistentHTTP::Connection.new(default_options.merge(options))
  [http, io]
end
