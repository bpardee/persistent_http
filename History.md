PersistentHttp Changelog
========================

2.0.1

 - Put default_path, host and port getters back into persistent_http for backwards compatibility

2.0.0

 - Separate out connection so a single dedicated connection can be used.
 - Allow non-persistent connections in case we just want the proxying stuff.

1.0.6

 - Fix pool_size and shutdown methods and make tests pass again (Matt Campbell - soupmatt)

1.0.5

 - Don't require 'net/https' in code.  JRuby 1.6.8 can have issues when 2 threads attempt to require it
   at the same time.

1.0.4

 - Added option :pool_timeout which will raise a Timeout::Error if unable to checkout a connection
   within this time.

1.0.3

 - Allow option idle_timeout which will renew connection that haven't been used in this amount of time.
 - Implement shutdown which will close connections as they are checked in.

1.0.2

 - Allow options to request to allow changing of read_timeout and possibly other params.
 - Add ECONNREFUSED as a retriable exception.

1.0.1

 - Bug fixes.
 - Forgot gene_pool dependency

1.0.0

 - Initial release
