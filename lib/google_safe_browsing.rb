require 'digest/sha2'
require 'net/http'
require 'redis'
require 'resolv'
require 'uri'

require_relative './canonicalize'

class GoogleSafeBrowsing
  $api_key = ''
  $redis = nil
  $debug = false

  $appver = '0.1'
  $pver = '2.2'

  # the lists we care about
  $lists = ["goog-malware-shavar", "googpub-phish-shavar"]

  @delay = Time.now

  # set the api key and redis object
  def initialize(api_key, options = {})
    $api_key = api_key
    $redis = options[:redis] || Redis.new
    $debug = options[:debug] || false
  end

  # request data from google's servers
  def update()
    say('Updating...')

    # checking if we need to wait longer before updating
    delay = $redis.get("delay")
    if(delay != '' && delay != nil)
      say("Error: must wait #{delay.to_i - Time.now.to_i} more seconds before updating! (#{delay})")
      return
    end

    # check what lists we have access to
    available_lists = get_lists()
    say("Available lists: #{available_lists.inspect}")

    # only download from lists we care about and have access to
    lists = (available_lists & $lists)

    get_data(lists)
  end

  # perform a lookup on a url
  def lookup(url)
    say("Checking url: #{url}")
    url, parts = canonicalize(url)
    hosts, paths = get_possible_hosts_paths(parts)

    # get all possible host+path combination hash prefixes
    full_urls = hosts.product(paths).collect{|a, b| a + b}
    prefixes = get_hash_prefixes(full_urls)
    full_url_hashes = get_hashes(full_urls)

    # add a trailing slash to all hosts, and get their hash prefixes
    host_hash_prefixes = get_hash_prefixes(hosts.collect{|a| a + '/'})

    host_num = 0
    $lists.each do |list|
      host_hash_prefixes.each do |host|
        is_member = $redis.sismember("#{list}:hosts", host)
        if(is_member)
          suffixes = $redis.smembers("#{list}:host_#{host}")
          hits = suffixes & prefixes
          if(suffixes.length == 0 || hits != [])
            full_hashes = get_full_hashes(hits)
            if(full_url_hashes & full_hashes != [])
              say("URL matches a list: #{list} (#{url})")
              return list
            end
          end
        end
        host_num += 1
      end
    end

    say("URL does not match any lists (#{url})")
    return ''
  end

  # returns the canonicalized url, and a hash of its parts
  def canonicalize(url)
    return Canonicalize::canonicalize(url)
  end

  def get_full_hashes(prefixes)
    body = "4:#{prefixes.length*4}\n"
    prefixes.each do |prefix|
      body += "#{[prefix].pack('H*')}"
    end

    response = api_request("gethash", body)
    if(response == nil)
      return []
    end

    response = StringIO.new(response)
    full_hashes = []
    while(line = response.gets)
      line = line.split(':')
      list = line[0]
      chunk_num = line[1].to_i
      chunk_len = line[2].to_i
      data = response.read(chunk_len)
      full_hashes.push(data.unpack("H*").join())
    end

    return full_hashes
  end

  # convert an array of strings into an array of 32 bit hash prefixes
  def get_hash_prefixes(items)
    prefixes = []
    items.each do |item|
      prefixes.push((Digest::SHA2.new << item).to_s[0..7])
    end

    return prefixes
  end

  # convert an array of strings into an array of hashes
  def get_hashes(items)
    hashes = []
    items.each do |item|
      hashes.push((Digest::SHA2.new << item).to_s)
    end

    return hashes
  end

  # expand a url into its possible host-path combinations according to the Google API
  def get_possible_hosts_paths(parts)
    case parts['host']
    when Resolv::IPv4::Regex
      ip = true
    when Resolv::IPv6::Regex
      ip = true
    else
      ip = false
    end

    # For the hostname, the client will try at most 5 different strings. They are:
    # - the exact hostname in the url
    # - up to 4 hostnames formed by starting with the last 5 components and successively removing the leading component.
    #   The top-level domain can be skipped. These additional hostnames should not be checked if the host is an IP address.
    possible_hosts = []

    if(!ip)
      host = parts['host'].split('.')
      [host.length - 2, 4].min.times do |i|
        possible_hosts.push(host[host.length-2-i..-1].join('.'))
      end
    end
    possible_hosts.push(parts['host'])
    possible_hosts.reverse!

    # For the path, the client will also try at most 6 different strings. They are:
    # - the exact path of the url, including query parameters
    # - the exact path of the url, without query parameters
    # - the 4 paths formed by starting at the root (/) and successively appending path components, including a trailing slash.
    possible_paths = []

    if(parts['query'] != '')
      possible_paths.push(parts['path'] + parts['query'])
    end
    possible_paths.push(parts['path'])

    path = parts['path'].split('/')
    [path.length - 1, 5].min.times do |i|
      possible_path = path[0..i].join('/')
      if(possible_path == '' || i < path.length - 1)
        possible_path += '/'
      end

      possible_paths.push(possible_path)
    end

    return possible_hosts, possible_paths
  end

  # returns available lists as an array
  def get_lists()
    lists = api_request("list")
    return lists.split("\n")
  end

  # performs a request for data from Google, and parses the response
  def get_data(lists)
    say('Getting data...')
    # build the request
    request_body = ''
    lists.each do |list|
      request_body += "#{list};"

      # append a:1,2,3,4,5,8
      add = get_add_chunks(list)
      if(add != '' && add != nil)
        request_body += "a:#{add}"
      end

      # append [:]s:6,7,9,11
      sub = get_sub_chunks(list)
      if(sub != '' && sub != nil)
        if(add != '' && add != nil)
          request_body += ":"
        end

        request_body += "s:#{sub}"
      end

      request_body += "\n"
    end

    say "Request body: #{request_body}"
    response = api_request("downloads", request_body)
    response = response.split("\n")

    # parse the response
    say('Handling response...')
    cur_list = ''
    redirects = {}
    response.each do |line|
      line = line.split(':')
      type = line[0]
      data = line[1]

      if(type == 'n')
        # set the next allowed time to poll
        delay = Time.now + data.to_i
        say("Time until next request: #{data}")
        $redis.setex("delay", data.to_i, delay.to_i)
      elsif(type == 'i')
        # set the current list
        cur_list = data
        redirects[cur_list] = []
        say("Current list: #{cur_list}")
      elsif(type == 'u')
        # store the redirect
        say("Redirect: #{data}")
        redirects[cur_list].push(data)
      elsif(type == 'ad')
        say("Delete chunks: #{data}")
        chunks = expand_ranges(data)
        delete_add_chunks(cur_list, chunks)
      elsif(type == 'sd')
        say("Don't report chunks: #{data}")
        chunks = expand_ranges(data)
        delete_sub_chunks(cur_list, chunks)
      else
        say("I don't know how to handle this!")
        say(line.inspect)
      end
    end

    # handle the redirects
    say('Handling redirects...')
    redirects.each do |list, urls|
      say("Handling #{list} redirects...")
      i = 0
      urls.each do |url|
        i += 1
        say("Handling #{list} redirect #{i} of #{urls.length}...")
        handle_redirect(list, url)
      end
    end
  end

  def delete_add_chunks(list, chunks)
    delete_chunks(list, 'add', chunks)
  end

  def delete_sub_chunks(list, chunks)
    delete_chunks(list, 'sub', chunks)
  end

  def delete_chunks(list, type, chunks)
    chunks.each do |chunk|
      if(type == 'add')
        # delete each of the prefixes
        hosts = $redis.smembers("#{list}:chunk_#{chunk}")
        hosts.each do |hosts|
          $redis.del("#{list}:host_#{host}")
          $redis.srem("#{list}:hosts", host)
        end

        # delete the list of prefixes
        $redis.del("#{list}:chunk_#{chunk}")
      end

      # delete from our chunk list
      $redis.srem("#{list}:#{type}_chunks", chunk)
    end
  end

  def get_add_chunks(list)
    return get_chunks(list, "add")
  end

  def get_sub_chunks(list)
    return get_chunks(list, "sub")
  end

  def get_chunks(list, type)
    chunks = $redis.smembers("#{list}:#{type}_chunks")
    return convert_list_to_ranges(chunks)
  end

  # reads and parses the encoded data from a redirect url
  def handle_redirect(list, url)
    response = http_post_request("http://#{url}")
    response = StringIO.new(response)

    while(line = response.gets)
      line = line.split(':')
      type = line[0]
      chunk_num = line[1].to_i
      hash_len = line[2].to_i
      chunk_len = line[3].to_i

      data = response.read(chunk_len)

      if(type == 'a')
        if(chunk_len == 0)
          # TODO
        end

        # store the chunk number in the add list
        store_add_chunk(list, chunk_num)

        entry_list = read_add_data(hash_len, data)

        # add all these prefixes
        add_entries(list, chunk_num, entry_list)
      elsif(type == 's')
        if(chunk_len == 0)
          # TODO
        end

        # store the chunk number in the sub list
        store_sub_chunk(list, chunk_num)

        entry_list = read_sub_data(hash_len, data)

        # delete all these prefixes
        sub_entries(list, chunk_num, entry_list)
      else
        say "I don't know how to handle this!"
        say line.inspect
      end
    end
  end

  def add_entries(list, chunk, entries)
    entries.each do |entry|
      $redis.sadd("#{list}:chunk_#{chunk}", entry['host'])
      $redis.sadd("#{list}:host_#{entry['host']}", entry['path'])
      $redis.sadd("#{list}:hosts", entry['host'])
    end
  end

  def sub_entries(list, chunk, entries)
    entries.each do |entry|
      $redis.srem("#{list}:chunk_#{chunk}", entry['host'])
      $redis.srem("#{list}:host_#{entry['host']}", entry['path'])
      $redis.srem("#{list}:hosts", entry['host'])
    end
  end

  def store_add_chunk(list, chunk)
    store_chunk(list, 'add', chunk)
  end

  def store_sub_chunk(list, chunk)
    store_chunk(list, 'sub', chunk)
  end

  def store_chunk(list, type, chunk)
    $redis.sadd("#{list}:#{type}_chunks", chunk)
  end

  def read_add_data(hash_len, data)
    return read_data(hash_len, data, false)
  end

  def read_sub_data(hash_len, data)
    return read_data(hash_len, data, true)
  end

  # reads a chunk of encoded data and converts it into a list of entries
  def read_data(hash_len, data, sub)
    # returns an array of hashes of the form: { host, path, chunk }
    entry_list = []
    addchunknum = ""

    data = StringIO.new(data)
    while(hostkey = data.read(4))
      hostkey = hostkey.unpack("H*")[0]
      count = data.read(1).unpack("H*")[0].hex # or .to_i(16)
      if(sub)
        addchunknum = data.read(4).unpack("H*")[0]
      end

      # If count > 1, it will be prefix-chunk until the last one, which will be just prefix
      count.times do |i|
        entry = {}
        entry['host'] = hostkey

        path_prefix = data.read(hash_len).unpack("H*")[0]
        entry['path'] = path_prefix

        if(sub && count > 1 && i != count-1)
          entry['chunk'] = data.read(4).unpack("H*")[0]
        else
          entry['chunk'] = addchunknum
        end

        entry_list.push(entry)
      end
    end

    return entry_list
  end

  # transforms "1-2,4-6,8" into [1,2,4,5,6,8]
  def expand_ranges(ranges)
    result = []
    ranges = ranges.split(',')
    ranges.each do |range|
      if(range.include? '-')
        range = range.split('-')
        a = range[0].to_i
        b = range[1].to_i
        [a..b].each do |i|
          result.push(i)
        end
      else
        result.push(range)
      end
    end

    return result
  end

  # transforms [1,2,4,5,6,8] into "1-2,4-6,8"
  def convert_list_to_ranges(list)
    ranges = list.collect{|s| s.to_i}.sort.uniq.inject([]) do |spans, n|
      if spans.empty? || spans.last.last != n - 1
        spans + [n..n]
      else
        spans[0..-2] + [spans.last.first..n]
      end
    end

    return ranges.join(',').gsub("..","-")
  end

  # makes a request to the google safe browsing api v2
  def api_request(function, body = nil)
    before = 'http://safebrowsing.clients.google.com/safebrowsing/'
    after = "?client=api&apikey=#{$api_key}&appver=#{$appver}&pver=#{$pver}"
    return http_post_request(before + function + after, body)
  end

  # makes an http post request with an empty body and returns the response
  def http_post_request(url, body = nil)
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Post.new(uri.request_uri)
    request.body = body || ''
    response = http.request(request)
    return response.body
  end

  def say(msg)
    if($debug)
      puts "#{Time.now.utc}: #{msg}"
    end
  end
end
