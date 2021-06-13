defmodule Cryptographer.Aes.Key.SchedulerTest do
  use ExUnit.Case
  alias Cryptographer.Aes.Key.Scheduler

  describe "expand_key/2" do
    test "returns a 128 bit binary" do
      key = <<0x00000000::32, 0x00000000::32, 0x00000000::32, 0x00000000::32>>

      assert <<_::128>> = Scheduler.expand_key(key, 1)
    end

    test "returns a 128 bit key correctly expanded for each round (first example)" do
      key = <<0xFFFFFFFF::32, 0xFFFFFFFF::32, 0xFFFFFFFF::32, 0xFFFFFFFF::32>>

      key = Scheduler.expand_key(key, 1)
      assert key == <<0xE8E9E9E9::32, 0x17161616::32, 0xE8E9E9E9::32, 0x17161616::32>>

      key = Scheduler.expand_key(key, 2)
      assert key == <<0xADAEAE19::32, 0xBAB8B80F::32, 0x525151E6::32, 0x454747F0::32>>

      key = Scheduler.expand_key(key, 3)
      assert key == <<0x090E2277::32, 0xB3B69A78::32, 0xE1E7CB9E::32, 0xA4A08C6E::32>>

      key = Scheduler.expand_key(key, 4)
      assert key == <<0xE16ABD3E::32, 0x52DC2746::32, 0xB33BECD8::32, 0x179B60B6::32>>

      key = Scheduler.expand_key(key, 5)
      assert key == <<0xE5BAF3CE::32, 0xB766D488::32, 0x045D3850::32, 0x13C658E6::32>>

      key = Scheduler.expand_key(key, 6)
      assert key == <<0x71D07DB3::32, 0xC6B6A93B::32, 0xC2EB916B::32, 0xD12DC98D::32>>

      key = Scheduler.expand_key(key, 7)
      assert key == <<0xE90D208D::32, 0x2FBB89B6::32, 0xED5018DD::32, 0x3C7DD150::32>>

      key = Scheduler.expand_key(key, 8)
      assert key == <<0x96337366::32, 0xB988FAD0::32, 0x54D8E20D::32, 0x68A5335D::32>>

      key = Scheduler.expand_key(key, 9)
      assert key == <<0x8BF03F23::32, 0x3278C5F3::32, 0x66A027FE::32, 0x0E0514A3::32>>

      key = Scheduler.expand_key(key, 10)
      assert key == <<0xD60A3588::32, 0xE472F07B::32, 0x82D2D785::32, 0x8CD7C326::32>>
    end

    test "returns a 128 bit key correctly expanded (second example)" do
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

      key = Scheduler.expand_key(key, 6)
      assert key == <<0xBD3DC287::32, 0xB87C4715::32, 0x6A6C9527::32, 0xAC2E0E4E::32>>

      key = Scheduler.expand_key(key, 7)
      assert key == <<0xCC96ED16::32, 0x74EAAA03::32, 0x1E863F24::32, 0xB2A8316A::32>>

      key = Scheduler.expand_key(key, 8)
      assert key == <<0x8E51EF21::32, 0xFABB4522::32, 0xE43D7A06::32, 0x56954B6C::32>>

      key = Scheduler.expand_key(key, 9)
      assert key == <<0xBFE2BF90::32, 0x4559FAB2::32, 0xA16480B4::32, 0xF7F1CBD8::32>>

      key = Scheduler.expand_key(key, 10)
      assert key == <<0x28FDDEF8::32, 0x6DA4244A::32, 0xCCC0A4FE::32, 0x3B316F26::32>>
    end

    test "returns a 128 bit key correctly expanded (third example)" do
      key = <<0x00000000::32, 0x00000000::32, 0x00000000::32, 0x00000000::32>>

      key = Scheduler.expand_key(key, 1)
      assert key == <<0x62636363::32, 0x62636363::32, 0x62636363::32, 0x62636363::32>>

      key = Scheduler.expand_key(key, 2)
      assert key == <<0x9B9898C9::32, 0xF9FBFBAA::32, 0x9B9898C9::32, 0xF9FBFBAA::32>>

      key = Scheduler.expand_key(key, 3)
      assert key == <<0x90973450::32, 0x696CCFFA::32, 0xF2F45733::32, 0x0B0FAC99::32>>

      key = Scheduler.expand_key(key, 4)
      assert key == <<0xEE06DA7B::32, 0x876A1581::32, 0x759E42B2::32, 0x7E91EE2B::32>>

      key = Scheduler.expand_key(key, 5)
      assert key == <<0x7F2E2B88::32, 0xF8443E09::32, 0x8DDA7CBB::32, 0xF34B9290::32>>

      key = Scheduler.expand_key(key, 6)
      assert key == <<0xEC614B85::32, 0x1425758C::32, 0x99FF0937::32, 0x6AB49BA7::32>>

      key = Scheduler.expand_key(key, 7)
      assert key == <<0x21751787::32, 0x3550620B::32, 0xACAF6B3C::32, 0xC61BF09B::32>>

      key = Scheduler.expand_key(key, 8)
      assert key == <<0x0EF90333::32, 0x3BA96138::32, 0x97060A04::32, 0x511DFA9F::32>>

      key = Scheduler.expand_key(key, 9)
      assert key == <<0xB1D4D8E2::32, 0x8A7DB9DA::32, 0x1D7BB3DE::32, 0x4C664941::32>>

      key = Scheduler.expand_key(key, 10)
      assert key == <<0xB4EF5BCB::32, 0x3E92E211::32, 0x23E951CF::32, 0x6F8F188E::32>>
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
