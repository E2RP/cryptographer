defmodule Cryptographer.Aes.BinaryUtils do
  alias Cryptographer.Aes

  @spec one_byte_left_rotate(word :: Aes.word()) :: Aes.word()
  def one_byte_left_rotate(<<a::8, b::8, c::8, d::8>>), do: <<b::8, c::8, d::8, a::8>>
  def one_byte_left_rotate([a, b, c, d]), do: [b, c, d, a]

  def bxor_binaries(a, b) do
    [a, b]
    |> Enum.map(&:binary.decode_unsigned/1)
    |> then(fn args -> apply(&Bitwise.bxor/2, args) end)
    |> :binary.encode_unsigned()
  end

  @spec bxor_words(word_a :: Aes.word_binary(), word_b :: Aes.word_binary()) :: Aes.word_binary()
  @spec bxor_words(
          word_a :: Aes.words_binary(),
          word_b :: Aes.words_binary(),
          acc :: [] | Aes.word_byte_list()
        ) :: Aes.word_byte_list()
  def bxor_words(word_a, word_b), do: word_a |> bxor_words(word_b, []) |> byte_list_to_word()
  defp bxor_words(<<>>, <<>>, acc), do: acc

  defp bxor_words(<<a::8, a_rest::binary>>, <<b::8, b_rest::binary>>, acc) do
    bxor_words(a_rest, b_rest, acc ++ [Bitwise.bxor(a, b)])
  end

  @spec binary_to_word_list(binary :: Aes.words_binary()) :: Aes.words_byte_list()
  def binary_to_word_list(binary), do: binary |> binary_to_word_list([]) |> Enum.reverse()

  defp binary_to_word_list(<<word::32, r::binary>>, acc),
    do: binary_to_word_list(r, [<<word::32>> | acc])

  defp binary_to_word_list(<<>>, acc), do: acc

  @spec multiple_words_to_byte_lists(binary :: <<_::_*4>>) :: [Aes.word_byte_list(), ...]
  @spec multiple_words_to_byte_lists(
          binary :: <<_::_*4>>,
          acc :: [] | [Aes.word_byte_list(), ...]
        ) :: [Aes.word_byte_list(), ...]
  def multiple_words_to_byte_lists(binary),
    do: binary |> multiple_words_to_byte_lists([]) |> Enum.reverse()

  defp multiple_words_to_byte_lists(<<>>, acc), do: acc

  defp multiple_words_to_byte_lists(<<word::32, rest::binary>>, acc) do
    <<word::32>> |> word_to_byte_list() |> then(&multiple_words_to_byte_lists(rest, [&1 | acc]))
  end

  @spec word_to_byte_list(word :: Aes.word_binary()) :: Aes.word_byte_list()
  def word_to_byte_list(<<a::8, b::8, c::8, d::8>>), do: [a, b, c, d]

  @spec byte_list_to_word(byte_list :: Aes.word_byte_list()) :: Aes.word_binary()
  def byte_list_to_word([a, b, c, d]), do: <<a::8, b::8, c::8, d::8>>
end
