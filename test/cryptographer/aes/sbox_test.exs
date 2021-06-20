defmodule Cryptographer.Aes.SBoxTest do
  use ExUnit.Case

  alias Cryptographer.Aes.SBox

  describe "sub_byte/1" do
    test "returns the value at given position in the substitution table" do
      assert SBox.sub_byte(255) == 0x16
      assert SBox.sub_byte(254) == 0xBB
      assert SBox.sub_byte(232) == 0x9B
      assert SBox.sub_byte(209) == 0x3E
      assert SBox.sub_byte(0) == 0x63
      assert SBox.sub_byte(40) == 0x34
      assert SBox.sub_byte(80) == 0x53
    end
  end

  describe "inverse_sub_byte/1" do
    test "returns the value at given position in the substitution table" do
      assert SBox.inverse_sub_byte(0x16) == 255
      assert SBox.inverse_sub_byte(0xBB) == 254
      assert SBox.inverse_sub_byte(0x9B) == 232
      assert SBox.inverse_sub_byte(0x3E) == 209
      assert SBox.inverse_sub_byte(0x63) == 0
      assert SBox.inverse_sub_byte(0x34) == 40
      assert SBox.inverse_sub_byte(0x53) == 80
    end
  end

  describe "sub_word/1" do
    test "returns a word binary with every byte correctly replaced when argument is a binary" do
      assert SBox.sub_word(<<65::8, 66::8, 67::8, 68::8>>) ==
               <<0x83::8, 0x2C::8, 0x1A::8, 0x1B::8>>

      assert SBox.sub_word(<<75::8, 75::8, 75::8, 75::8>>) ==
               <<0xB3::8, 0xB3::8, 0xB3::8, 0xB3::8>>

      assert SBox.sub_word(<<87::8, 88::8, 89::8, 90::8>>) ==
               <<0x5B::8, 0x6A::8, 0xCB::8, 0xBE::8>>
    end

    test "returns a word binary with every byte correctly replaced when argument is a list" do
      assert SBox.sub_word([65, 66, 67, 68]) == [0x83, 0x2C, 0x1A, 0x1B]
      assert SBox.sub_word([75, 75, 75, 75]) == [0xB3, 0xB3, 0xB3, 0xB3]
      assert SBox.sub_word([87, 88, 89, 90]) == [0x5B, 0x6A, 0xCB, 0xBE]
    end
  end

  describe "inverse_sub_word/1" do
    test "returns a word binary with every byte correctly replaced when argument is a binary" do
      assert SBox.inverse_sub_word(<<0x83::8, 0x2C::8, 0x1A::8, 0x1B::8>>) ==
               <<65::8, 66::8, 67::8, 68::8>>

      assert SBox.inverse_sub_word(<<0xB3::8, 0xB3::8, 0xB3::8, 0xB3::8>>) ==
               <<75::8, 75::8, 75::8, 75::8>>

      assert SBox.inverse_sub_word(<<0x5B::8, 0x6A::8, 0xCB::8, 0xBE::8>>) ==
               <<87::8, 88::8, 89::8, 90::8>>
    end

    test "returns a word binary with every byte correctly replaced when argument is a list" do
      assert SBox.inverse_sub_word([0x83, 0x2C, 0x1A, 0x1B]) == [65, 66, 67, 68]
      assert SBox.inverse_sub_word([0xB3, 0xB3, 0xB3, 0xB3]) == [75, 75, 75, 75]
      assert SBox.inverse_sub_word([0x5B, 0x6A, 0xCB, 0xBE]) == [87, 88, 89, 90]
    end
  end
end
