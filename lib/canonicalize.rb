require 'ip'
require 'uri'

class Canonicalize
  def self.canonicalize(url)
    url.strip!

    # Remove any tab (0x09), CR (0x0d), and LF (0x0a) characters from the URL
    url = url.gsub('  ','').gsub("\n",'').gsub("\r",'')

    # If the URL ends in a fragment, the fragment should be removed
    url = url.split('#')[0]

    # Repeatedly URL-unescape the URL until it has no more hex-encodings
    while(url != URI.unescape(url))
      url = URI.unescape(url)
    end

    # Extract the hostname from the URL
    protocol = url.split('://')[0]
    if(protocol == nil || !url.include?('://'))
      protocol = "http://"
      host = url.split('/')[0]
      path = url.sub(host, '')
    else
      protocol += "://"
      host = url.sub(protocol, '').split('/')[0]
      path = url.sub(protocol, '').sub(host, '')
    end

    query = ''
    if(path.include?('?'))
      query = path[path.index('?')..-1]
      path = path.sub(query, '')
    end

    # Remove all leading and trailing dots
    host.gsub!(/\A\.+|\.+\Z/, '')

    # Replace consecutive dots with a single dot
    host.gsub!(/\.+/, '.')

    # If the hostname can be parsed as an IP address, it should be normalized to 4 dot-separated decimal values.
    # The client should handle any legal IP- address encoding, including octal, hex, and fewer than 4 components.
    if(host.match(/^\d+$/))
      host = IP::V4.new(host.to_i).to_addr
    end

    # Lowercase the whole string
    protocol.downcase!
    host.downcase!

    # The sequences "/../" and "/./" in the path should be resolved,
    # by replacing "/./" with "/", and removing "/../" along with the preceding path component.
    path = path.gsub('/./', '/')
    trailing = path[-1..-1] == '/'
    path_parts = path.split('/')
    path = []
    path_parts.each do |part|
      if(part == '..')
        path.pop
      else
        path.push(part)
      end
    end
    path = path.join('/')
    if(path == '' || trailing)
      path += '/'
    end

    # Runs of consecutive slashes should be replaced with a single slash character
    path.gsub!(/\/+/, '/')

    # After performing these steps, percent-escape all characters in the URL which are <= ASCII 32, >= 127, "#", or "%".
    # The escapes should use uppercase hex characters.
    protocol = URI.escape(protocol).gsub('%5E', '^')
    host = URI.escape(host).gsub('%5E', '^')
    path = URI.escape(path).gsub('%5E', '^')
    query = URI.escape(query).gsub('%5E', '^')

    host = remove_user_password_and_port(host)

    url = protocol + host + path + query

    return url, { 'protocol' => protocol, 'host' => host, 'path' => path, 'query' => query }
  end

  def self.remove_user_password_and_port(host)
    if(host.include?('@'))
      host = host.split('@')[1]
    end

    if(host.include?(':'))
      host = host.split(':')[0]
    end

    return host
  end
end
