require 'digest'
require_relative './helpers/ec'

hello = "Hello World"
sha256 = Digest::SHA256.new
digest = sha256.digest hello

puts "Sha256:" + digest

def main
  ec = EllipticCurve.new

  puts "Keypair:"
  puts "Priv: #{ec.pkey}"
  puts "Publ: #{ec.pub}"

  pub = ec.pub
  components = ec.get_components(pub)
  pretty_print components

  components = ec.get_components(ec.get_compressed(pub))
  pretty_print components
end

def pretty_print (pub_components)
  puts "\nType: #{pub_components[:type]}"
  puts "x: #{pub_components[:x]}, size: #{pub_components[:x].size }"
  puts "y: #{pub_components[:y]}, size: #{pub_components[:y].size }" if pub_components[:y].size != 0
end

main()