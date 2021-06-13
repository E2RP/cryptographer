defmodule Cryptographer.Aes.Key.SchedulerTest do
  use ExUnit.Case
  alias Cryptographer.Aes.Key.Scheduler

  describe "expand_key/2" do
    test "returns a 128 bit binary" do
      key =
        <<255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8,
          255::8, 255::8, 255::8, 255::8, 255::8>>

      assert <<_::128>> = Scheduler.expand_key(key, 1)
    end

    test "returns a 128 bit key correctly expanded for each round (first example)" do
      key =
        <<255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8, 255::8,
          255::8, 255::8, 255::8, 255::8, 255::8>>

      assert Scheduler.expand_key(key, 1) ==
               <<0xE8E9E9E9::32, 0x17161616::32, 0xE8E9E9E9::32, 0x17161616::32>>
    end

    test "returns a 128 bit key correctly expanded (second example)" do
      key = <<0x54686174::32, 0x73206D79::32, 0x204B756E::32, 0x67204675::32>>

      key = Scheduler.expand_key(key, 1)
      assert key == <<0xE232FCF1::32, 0x91129188::32, 0xB159E4E6::32, 0xD679A293::32>>

      key = Scheduler.expand_key(key, 2)
      assert key == <<0x56082007::32, 0xC71AB18F::32, 0x76435569::32, 0xA03AF7FA::32>>

      key = Scheduler.expand_key(key, 3)
      assert key == <<0xD2600DE7::32, 0x157ABC68::32, 0x6339E901::32, 0xC3031EFB::32>>
    end

    test "automated" do
      key = <<0x54686174::32, 0x73206D79::32, 0x204B756E::32, 0x67204675::32>>

      key = Scheduler.expand_key(key, 1)
      assert key == <<0xE232FCF1::32, 0x91129188::32, 0xB159E4E6::32, 0xD679A293::32>>

      key = Scheduler.expand_key(key, 2)
      assert key == <<0x56082007::32, 0xC71AB18F::32, 0x76435569::32, 0xA03AF7FA::32>>

      key = Scheduler.expand_key(key, 3)
      assert key == <<0xD2600DE7::32, 0x157ABC68::32, 0x6339E901::32, 0xC3031EFB::32>>

      key = Scheduler.expand_key(key, 4)
      assert key == <<0xA11202C9::32, 0xB468BEA1::32, 0xD75157A0::32, 0x1452495B::32>>

      key = Scheduler.expand_key(key, 5)
      assert key == <<0xB1293B33::32, 0x05418592::32, 0xD210D232::32, 0xC6429B69::32>>

      key = Scheduler.expand_key(key, 6) |> IO.inspect(label: :result, binaries: :as_binaries)

      assert key ==
               <<0xBD3DC2B7::32, 0xB87C4715::32, 0x6A6C9527::32, 0xAC2E0E4E::32>>
               |> IO.inspect(label: :expect, binaries: :as_binaries)

      # key = Scheduler.expand_key(key, 7)
      # assert key == <<0xCC96ED16::32, 0x74EAAA03::32, 0x1E863F24::32, 0xB2A8316A::32>>

      # key = Scheduler.expand_key(key, 8)
      # assert key == <<0x8E51EF21::32, 0xFABB4522::32, 0xE43D7A06::32, 0x56954B6C::32>>

      # key = Scheduler.expand_key(key, 9)
      # assert key == <<0xBFE2BF90::32, 0x4559FAB2::32, 0xA16480B4::32, 0xF7F1CBD8::32>>

      # key = Scheduler.expand_key(key, 10)
      # assert key == <<0x28FDDEF8::32, 0x6DA4244A::32, 0xCCC0A4FE::32, 0x3B316F26::32>>
    end
  end

  describe "one_byte_left_rotate_word/1" do
    test "returns a string rotated one byte to the left when argument is a string" do
      assert Scheduler.one_byte_left_rotate("ABCD") == "BCDA"
      assert Scheduler.one_byte_left_rotate("DABC") == "ABCD"
      assert Scheduler.one_byte_left_rotate("WXYZ") == "XYZW"
    end

    test "returns a binary rotated one byte to the left when argument is a binary" do
      assert Scheduler.one_byte_left_rotate(<<1::8, 2::8, 3::8, 4::8>>) ==
               <<2::8, 3::8, 4::8, 1::8>>

      assert Scheduler.one_byte_left_rotate(<<255::8, 0::8, 78::8, 96::8>>) ==
               <<0::8, 78::8, 96::8, 255::8>>

      assert Scheduler.one_byte_left_rotate(<<127::8, 65::8, 30::8, 47::8>>) ==
               <<65::8, 30::8, 47::8, 127::8>>
    end

    test "returns a list rotated one byte to the left when argument is a list" do
      assert Scheduler.one_byte_left_rotate([1, 2, 3, 4]) == [2, 3, 4, 1]
      assert Scheduler.one_byte_left_rotate([255, 0, 30, 47]) == [0, 30, 47, 255]
      assert Scheduler.one_byte_left_rotate([127, 65, 30, 47]) == [65, 30, 47, 127]
    end
  end

  describe "sub_word/1" do
    test "returns a word with every byte correclty replaced according to the AES table" do
      assert Scheduler.sub_word("ABCD") == <<0x83::8, 0x2C::8, 0x1A::8, 0x1B::8>>
      assert Scheduler.sub_word("KKKK") == <<0xB3::8, 0xB3::8, 0xB3::8, 0xB3::8>>
      assert Scheduler.sub_word("WXYZ") == <<0x5B::8, 0x6A::8, 0xCB::8, 0xBE::8>>
    end
  end

  describe "round_constant/1" do
    test "returns the round constant correctly calculated regardig the round number" do
      assert Scheduler.compute_round_constant(1) == <<0x01::8, 0x00::8, 0x00::8, 0x00::8>>
      assert Scheduler.compute_round_constant(2) == <<0x02::8, 0x00::8, 0x00::8, 0x00::8>>
      assert Scheduler.compute_round_constant(3) == <<0x04::8, 0x00::8, 0x00::8, 0x00::8>>
      assert Scheduler.compute_round_constant(4) == <<0x08::8, 0x00::8, 0x00::8, 0x00::8>>
      assert Scheduler.compute_round_constant(5) == <<0x10::8, 0x00::8, 0x00::8, 0x00::8>>
      assert Scheduler.compute_round_constant(6) == <<0x20::8, 0x00::8, 0x00::8, 0x00::8>>
      assert Scheduler.compute_round_constant(7) == <<0x40::8, 0x00::8, 0x00::8, 0x00::8>>
      assert Scheduler.compute_round_constant(8) == <<0x80::8, 0x00::8, 0x00::8, 0x00::8>>
      assert Scheduler.compute_round_constant(9) == <<0x1B::8, 0x00::8, 0x00::8, 0x00::8>>
      assert Scheduler.compute_round_constant(10) == <<0x36::8, 0x00::8, 0x00::8, 0x00::8>>
    end
  end
end
