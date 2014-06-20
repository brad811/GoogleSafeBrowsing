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

# The lookup method will return the list name if the given url appears on a list,
# or an empty string if the url doesn not appear on any lists

# Return value: 'goog-malware-shavar'
checker.lookup('http://malware.testing.google.test/testing/malware/')

# Return value: ''
checker.lookup('http://www.google.com/')

```
