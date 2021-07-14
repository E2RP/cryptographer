defmodule Cryptographer.Aes.RijndaelGaloisFieldTest do
  use ExUnit.Case
  alias Cryptographer.Aes.RijndaelGaloisField, as: GF

  describe "add/2" do
    test "returns the xor of the given numbers" do
      assert GF.add(42, 42) == 0
      assert GF.add(0b10010001, 0b01101110) == 0b11111111
      assert GF.add(0xFB, 0xBA) == 0x41
    end
  end

  describe "multiply/2" do
    test "returns the remaining of the multiplication of the parameters by the reducing polynomial" do
      assert GF.multiply(0b01010011, 0b11001010) == 0b1
    end
  end
end
