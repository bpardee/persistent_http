PersistentHttp Changelog
========================

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

