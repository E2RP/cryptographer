defmodule Cryptographer.Aes.RijndaelGaloisField do
  @moduledoc """
  As a very unique galois field, Rijndael's finite field,
  denoted as GF(2^8) used in AES, comprises different
  operations with "extra steps".
  """

  # The reducing polynomial for GF(2^8) is
  # x^8 + x^4 + x^3 + x + 1
  @reducing_polynomial 0b100011011

  @spec add(a :: integer(), b :: integer()) :: integer()
  def add(a, b), do: Bitwise.bxor(a, b)

  @spec multiply(a :: integer(), b :: integer()) :: integer()
  def multiply(a, b), do: rem(a * b, @reducing_polynomial)
end
