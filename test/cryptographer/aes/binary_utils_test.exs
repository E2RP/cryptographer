defmodule Cryptographer.Aes.BinaryUtilsTest do
  use ExUnit.Case
  alias Cryptographer.Aes.BinaryUtils

  describe "one_byte_left_rotate/1" do
    test "returns a binary rotated one byte to the left when argument is a binary" do
      assert BinaryUtils.one_byte_left_rotate(<<1::8, 2::8, 3::8, 4::8>>) ==
               <<2::8, 3::8, 4::8, 1::8>>

      assert BinaryUtils.one_byte_left_rotate(<<255::8, 0::8, 78::8, 96::8>>) ==
               <<0::8, 78::8, 96::8, 255::8>>

      assert BinaryUtils.one_byte_left_rotate(<<127::8, 65::8, 30::8, 47::8>>) ==
               <<65::8, 30::8, 47::8, 127::8>>
    end

    test "returns a list rotated one byte to the left when argument is a list" do
      assert BinaryUtils.one_byte_left_rotate([1, 2, 3, 4]) == [2, 3, 4, 1]
      assert BinaryUtils.one_byte_left_rotate([255, 0, 30, 47]) == [0, 30, 47, 255]
      assert BinaryUtils.one_byte_left_rotate([127, 65, 30, 47]) == [65, 30, 47, 127]
    end
  end

  describe "bxor_words/2" do
    test "it returns a binary with the result of xor between the arguments" do
      assert BinaryUtils.bxor_words(<<1::8, 2::8, 3::8, 4::8>>, <<255::8, 0::8, 30::8, 47::8>>) ==
               <<254::8, 2::8, 29::8, 43::8>>

      assert BinaryUtils.bxor_words(<<1::8, 2::8, 3::8, 4::8>>, <<127::8, 65::8, 30::8, 47::8>>) ==
               <<126::8, 67::8, 29::8, 43::8>>

      assert BinaryUtils.bxor_words(
               <<127::8, 65::8, 30::8, 47::8>>,
               <<255::8, 0::8, 30::8, 47::8>>
             ) == <<128::8, 65::8, 0::8, 0::8>>
    end
  end

  describe "binary_to_word_list/1" do
    test "it returns a list containing of all the argument's binary words" do
      assert BinaryUtils.binary_to_word_list(
               <<1::8, 2::8, 3::8, 4::8, 255::8, 0::8, 30::8, 47::8>>
             ) ==
               [<<1::8, 2::8, 3::8, 4::8>>, <<255::8, 0::8, 30::8, 47::8>>]

      assert BinaryUtils.binary_to_word_list(
               <<1::8, 2::8, 3::8, 4::8, 127::8, 65::8, 30::8, 47::8>>
             ) ==
               [<<1::8, 2::8, 3::8, 4::8>>, <<127::8, 65::8, 30::8, 47::8>>]

      assert BinaryUtils.binary_to_word_list(
               <<127::8, 65::8, 30::8, 47::8, 255::8, 0::8, 30::8, 47::8>>
             ) ==
               [<<127::8, 65::8, 30::8, 47::8>>, <<255::8, 0::8, 30::8, 47::8>>]
    end
  end

  describe "multiple_words_to_byte_lists/1" do
    test "it returns a list containing of all the argument's bytes" do
      assert BinaryUtils.multiple_words_to_byte_lists(
               <<1::8, 2::8, 3::8, 4::8, 255::8, 0::8, 30::8, 47::8>>
             ) ==
               [[1, 2, 3, 4], [255, 0, 30, 47]]

      assert BinaryUtils.multiple_words_to_byte_lists(
               <<1::8, 2::8, 3::8, 4::8, 127::8, 65::8, 30::8, 47::8>>
             ) ==
               [[1, 2, 3, 4], [127, 65, 30, 47]]

      assert BinaryUtils.multiple_words_to_byte_lists(
               <<127::8, 65::8, 30::8, 47::8, 255::8, 0::8, 30::8, 47::8>>
             ) ==
               [[127, 65, 30, 47], [255, 0, 30, 47]]
    end
  end

  describe "byte_list_to_word/1" do
    test "it returns a binary with the same bytes as the list" do
      assert BinaryUtils.byte_list_to_word([1, 2, 3, 4]) == <<1::8, 2::8, 3::8, 4::8>>
      assert BinaryUtils.byte_list_to_word([255, 0, 30, 47]) == <<255::8, 0::8, 30::8, 47::8>>
      assert BinaryUtils.byte_list_to_word([127, 65, 30, 47]) == <<127::8, 65::8, 30::8, 47::8>>
    end
  end

  describe "word_to_byte_list/1" do
    assert BinaryUtils.word_to_byte_list(<<1::8, 2::8, 3::8, 4::8>>) == [1, 2, 3, 4]
    assert BinaryUtils.word_to_byte_list(<<255::8, 0::8, 30::8, 47::8>>) == [255, 0, 30, 47]
    assert BinaryUtils.word_to_byte_list(<<127::8, 65::8, 30::8, 47::8>>) == [127, 65, 30, 47]
  end
end
