require 'digest'
require_relative './helpers/ec'

hello = "Hello World"
sha256 = Digest::SHA256.new
digest = sha256.digest hello

puts "Sha256:" + digest

def main
  ec = EllipticCurve.new

  pub = ec.pub
  ec.pretty_print(pub)
  ec.pretty_print(ec.compressed(pub))
end

main()