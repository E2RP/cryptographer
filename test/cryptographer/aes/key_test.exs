defmodule Cryptographer.Aes.KeyTest do
  use ExUnit.Case

  alias Cryptographer.Aes.Key

  describe "generate/0" do
    test "returns a randomly generated key of 128 bits (16 characters)" do
      assert String.length(Key.generate()) == 16
      assert String.length(Key.generate()) == 16
      assert String.length(Key.generate()) == 16
    end
  end

  describe "one_byte_left_rotate_word/1" do
    test "returns a rotated word by one byte" do
      assert "ABCD" |> separate_string_characters() |> Key.one_byte_left_rotate_word() == "BCDA"
      assert "DABC" |> separate_string_characters() |> Key.one_byte_left_rotate_word() == "ABCD"
      assert "WXYZ" |> separate_string_characters() |> Key.one_byte_left_rotate_word() == "XYZW"
      assert "ZYXW" |> separate_string_characters() |> Key.one_byte_left_rotate_word() == "YXWZ"
    end
  end

  describe "sub_word/1" do
    test "returns a word with every byte correclty replaced according to the AES table" do
      assert Key.sub_word("ABCD") == [0x83, 0x2C, 0x1A, 0x1B]
      assert Key.sub_word("KKKK") == [0xB3, 0xB3, 0xB3, 0xB3]
      assert Key.sub_word("WXYZ") == [0x5B, 0x6A, 0xCB, 0xBE]
    end
  end

  describe "round_constant/1" do
    test "returns the round constant correctly calculated regardig the round number" do
      assert Key.round_constant(1) == 0x01
      assert Key.round_constant(2) == 0x02
      assert Key.round_constant(3) == 0x04
      assert Key.round_constant(4) == 0x08
      assert Key.round_constant(5) == 0x10
      assert Key.round_constant(6) == 0x20
      assert Key.round_constant(7) == 0x40
      assert Key.round_constant(8) == 0x80
      assert Key.round_constant(9) == 0x100
      assert Key.round_constant(10) == 0x200
    end
  end

  defp separate_string_characters(string), do: String.graphemes(string)
end
