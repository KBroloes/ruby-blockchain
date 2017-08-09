require_relative '../helpers/ec'
require 'securerandom'

def rand(size)
  SecureRandom.hex(size)
end

describe EllipticCurve do
  ec = EllipticCurve.new()

  describe "initialize" do
    it "generates a new ec keypair" do
      expect(ec.pub).to be_truthy
      expect(ec.pub).to start_with '04'
      expect(ec.pub.size).to be 2 + 64 + 64

      expect(ec.pkey).to be_truthy
      expect(ec.pkey.size).to be 64
    end
  end

  describe "get_components" do
    it "returns the components of a public key" do
      expected_x = rand 32
      expected_y = rand 32
      fake_pub = '04' + expected_x + expected_y

      components = ec.get_components(fake_pub)

      expect(components[:type]).to eql '04'
      expect(components[:x]).to eql expected_x
      expect(components[:x].size).to eql 64
      expect(components[:y]).to eql expected_y
      expect(components[:y].size).to eql 64
    end
  end

  describe "get_compressed" do
    it "compresses a public key by removing the Y component and prefixing the X component" do
      expected_x = rand 32
      expected_y = rand 32
      fake_pub = '04' + expected_x + expected_y

      expected_prefix = ec.get_prefix expected_y

      compressed = ec.get_compressed fake_pub

      expect(compressed).to eql (expected_prefix + expected_x)
    end
  end

  describe "get_prefix" do

    it "returns '02' on even hex strings" do
      prefix = ec.get_prefix '52'

      expect(prefix).to eql '02'
    end

    it "returns '03' on odd hex strings" do
      prefix = ec.get_prefix '53'

      expect(prefix).to eql '03'
    end
  end
end