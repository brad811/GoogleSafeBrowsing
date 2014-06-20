GoogleSafeBrowsing
==================

A ruby implementation of the Google Safe Browsing API v2 that uses Redis

## Installation

    gem install google_safe_browsing_redis

## Example Usage

```ruby
require 'google_safe_browsing'

api_key = 'YOUR_GOOGLE_SAFE_BROWSING_V2_API_KEY'

# A few example valid initializations
checker = GoogleSafeBrowsing.new(api_key)
checker = GoogleSafeBrowsing.new(api_key, :redis => Redis.new )
checker = GoogleSafeBrowsing.new(api_key, :debug => true )
checker = GoogleSafeBrowsing.new(api_key, :redis => Redis.new, :debug => false)

# This will update your database
checker.update()

# This url should report that it is on the malware list
checker.lookup('http://malware.testing.google.test/testing/malware/')

# This url should not match any lists
checker.lookup('http://www.google.com/')

```
