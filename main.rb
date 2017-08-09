require 'digest'
require __dir__ + '/helpers/ec'

hello = "Hello World"
sha256 = Digest::SHA256.new
digest = sha256.digest hello

puts "Sha256:" + digest

def main
  ec_generate
end

main()