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
end
