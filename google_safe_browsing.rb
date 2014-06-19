require 'net/http'
require 'redis'
require 'uri'

require_relative './canonicalize'

class GoogleSafeBrowsing
	$api_key = ''
	$redis = nil

	$appver = '0.1'
	$pver = '2.2'

	# the lists we care about
	$lists = ["goog-malware-shavar", "googpub-phish-shavar"]

	$debug = true

	@delay = Time.now

	# set up the object
	def initialize(api_key, redis = nil)
		say('Initializing...')
		$api_key = api_key
		$redis = redis || Redis.new
	end

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

	# returns available lists as an array
	def get_lists()
		lists = api_request("list")
		return lists.split("\n")
	end

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

		say("Request body: #{request_body.inspect}")

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
				keys = $redis.smembers("#{list}:#{chunk}")
				keys.each do |key|
					$redis.del("#{list}:#{chunk}:#{key}")
				end

				# delete the list of prefixes
				$redis.del("#{list}:#{chunk}")
			end

			# delete from our chunk list
			$redis.srem("#{list}:#{type}_chunks", chunk)
		end
	end

	def get_chunks(list, type)
		chunks = $redis.smembers("#{list}:#{type}_chunks")

		ranges = chunks.collect{|s| s.to_i}.sort.uniq.inject([]) do |spans, n|
			if spans.empty? || spans.last.last != n - 1
				spans + [n..n]
			else
				spans[0..-2] + [spans.last.first..n]
			end
		end

		return ranges.join(',').gsub("..","-")
	end

	def get_add_chunks(list)
		return get_chunks(list, "add")
	end

	def get_sub_chunks(list)
		return get_chunks(list, "sub")
	end

	def handle_redirect(list, url)
		response = http_post_request("http://#{url}")
		response = StringIO.new(response)

		while(line = response.gets)
			#puts line

			line = line.split(':')
			type = line[0]
			chunk_num = line[1].to_i
			hash_len = line[2].to_i
			chunk_len = line[3].to_i

			data = response.read(chunk_len)
			#puts "data length: #{data.length}, data: ========================================"
			#puts data.unpack("H*")
			#puts "================================================================================"

			if(type == 'a')
				if(chunk_len == 0)
					# TODO: something?
				end

				# store the chunk number in the add list
				store_add_chunk(list, chunk_num)

				entry_list = read_add_data(hash_len, data)

				# add all these prefixes
				add_entries(list, chunk_num, entry_list)
			elsif(type == 's')
				if(chunk_len == 0)
					# TODO: something?
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
			$redis.sadd("#{list}:#{chunk}", entry['host'])
			$redis.sadd("#{list}:#{chunk}:#{entry['host']}", entry['path'])
		end
	end

	def sub_entries(list, chunk, entries)
		entries.each do |entry|
			$redis.srem("#{list}:#{entry['chunk']}", entry['host'])
			$redis.srem("#{list}:#{entry['chunk']}:#{entry['host']}", entry['path'])
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

	def read_data(hash_len, data, sub)
		# returns an array of hashes of the form: { host, path, chunk }
		entry_list = []
		addchunknum = ""

		data = StringIO.new(data)
		while(hostkey = data.read(4))
			hostkey = hostkey.unpack("H*")[0]
			#puts "hostkey: #{hostkey}"
			count = data.read(1).unpack("H*")[0].hex # or .to_i(16)
			#puts "count: #{count}"
			if(sub)
				addchunknum = data.read(4).unpack("H*")[0]
				#puts "addchunknum: #{addchunknum}"
			end

			# If count > 1, it will be prefix-chunk until the last one, which will be just prefix
			count.times do |i|
				entry = {}
				entry['host'] = hostkey

				path_prefix = data.read(hash_len).unpack("H*")[0]
				#puts "path_prefix: #{path_prefix}"
				entry['path'] = path_prefix

				if(sub && count > 1 && i != count-1)
					entry['chunk'] = data.read(4).unpack("H*")[0]
				else
					entry['chunk'] = addchunknum
				end
				#puts "chunk: #{entry['chunk']}"

				entry_list.push(entry)
			end
		end

		#puts "----------"
		return entry_list
	end

	# transforms "1-2,4-5,7" into [1,2,4,5,7]
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
		response = http.request(request).body
		return response
	end

	def say(msg)
		if($debug)
			puts "#{Time.now.utc}: #{msg}"
		end
	end
end
