require 'openssl'

class EllipticCurve
  COMPRESSED = '02'
  UNCOMPRESSED = '04'

  attr_reader :pkey, :pub

  def initialize
    ec = OpenSSL::PKey::EC.new('secp256k1')

    ec.generate_key

    @pkey = ec.private_key.to_s 16 # Returns BigNum, convert to base16 (hex)
    @pub = ec.public_key.to_bn.to_s 16 # Convert to BigNum so we can get the hex value

    puts "Keypair:"
    puts "Priv: #{pkey}"
    puts "Publ: #{pub}"
  end

  def pretty_print(pub)
    block_size = 32 * 2  # 32 bytes in hex
    type_size = 2        # 1 byte in hex

    key = pub.split(//)

    type = key.take(type_size).join
    x = key.drop(type_size).take(block_size).join
    y = key.drop(type_size + block_size).take(block_size).join if type.eql? UNCOMPRESSED

    puts "\nType: #{type}"
    puts "x: #{x}, size: #{x.size }"
    puts "y: #{y}, size: #{y.size }" if type.eql? UNCOMPRESSED
  end

  def compressed(pub)
    COMPRESSED.concat pub.split(//).drop(2).take(64).join
  end
end

