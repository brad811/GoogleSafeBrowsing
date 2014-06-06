require 'net/http'
require 'redis'
require 'uri'

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
			# TODO: then append all a and s chunks we have
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
				# TODO: store in redis
			elsif(type == 'i')
				# set the current list
				cur_list = data
				redirects[cur_list] = []
				say("Current list: #{cur_list}")
			elsif(type == 'u')
				# store the redirect
				redirects[cur_list].push(data)
				say("Redirect: #{data}")
			elsif(type == 'ad')
				# TODO: delete chunks for current list
				say("Delete chunks: #{data}")
			elsif(type == 'sd')
				# TODO: delete chunks for current list
				say("Don't report chunks: #{data}")
			else
				say("I don't know how to handle this!")
				say(line.inspect)
			end
		end

		# handle the redirects
		say('Handling redirects...')
		redirects.each do |list, urls|
			urls.each do |url|
				handle_redirect(list, url)
			end
		end
	end

	def handle_redirect(list, url)
		response = http_post_request("http://#{url}")
		response = StringIO.new(response)

		while(line = response.gets)
			puts line

			line = line.split(':')
			type = line[0]
			chunk_num = line[1].to_i
			hash_len = line[2].to_i
			chunk_len = line[3].to_i

			data = response.read(chunk_len)
			puts "data length: #{data.length}, data: ========================================"
			puts data.unpack("H*")
			puts "================================================================================"

			if(type == 'a')
				if(chunk_len == 0)
				end
				# TODO: store the chunk number in the add list
				prefix_list = read_add_data(hash_len, data)
				# TODO: add all these prefixes
			elsif(type == 's')
				if(chunk_len == 0)
				end
				# TODO: store the chunk number in the add list
				prefix_list = read_sub_data(hash_len, data)
				# TODO: delete all these prefixes
			else
				say "I don't know how to handle this!"
				say line.inspect
			end
		end
	end

	def read_add_data(hash_len, data)
		return read_data(hash_len, data, false)
	end

	def read_sub_data(hash_len, data)
		return read_data(hash_len, data, true)
	end

	def read_data(hash_len, data, sub)
		prefix_list = []

		data = StringIO.new(data)
		while(hostkey = data.read(8))
			count = data.read(2).hex # or .to_i(16)
			if(sub)
				addchunknum = data.read(8))
			end
			count.times do
				prefix = data.read(hash_len * 2)
				prefix_list.push(prefix)
			end
		end

		return prefix_list
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
