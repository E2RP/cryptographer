defmodule Cryptographer.Aes.Key.Scheduler do
  alias Cryptographer.Aes
  alias Cryptographer.Aes.Key
  alias Cryptographer.Aes.Table

  @spec expand_key(key :: Key.t(), round :: pos_integer()) :: [Aes.word(), ...]
  def expand_key(key, round) when is_binary(key) and round >= 1 do
    IO.puts("\n\n")
    round_words = binary_to_word_list(key)

    round_words
    |> Enum.with_index()
    |> Enum.reduce(round_words, fn {word, i}, acc ->
      next_word =
        case i do
          0 -> bxor_words(word, g_function(Enum.at(acc, i + 3), round))
          i -> bxor_words(Enum.at(acc, i + 3), Enum.at(acc, i))
        end
        IO.inspect({next_word, i}, label: "step")

      acc ++ [next_word]
    end)
    |> Enum.take(-4)
    |> Enum.into(<<>>, fn <<a::8, b::8, c::8, d::8>> -> <<a::8, b::8, c::8, d::8>> end)
  end

  @spec one_byte_left_rotate(word :: Aes.word() | [non_neg_integer(), ...]) ::
          Aes.word() | [non_neg_integer(), ...]
  def one_byte_left_rotate(<<a::8, b::8, c::8, d::8>>), do: <<b::8, c::8, d::8, a::8>>
  def one_byte_left_rotate([a, b, c, d]), do: [b, c, d, a]

  @spec sub_word(word :: Aes.word()) :: Aes.word()
  @spec sub_word(binary(), acc :: list(non_neg_integer())) :: list(non_neg_integer())
  def sub_word(word), do: word |> sub_word([]) |> Enum.reverse() |> byte_list_to_word()
  defp sub_word(<<>>, acc), do: acc
  defp sub_word(<<byte::8, rest::binary>>, acc), do: sub_word(rest, [sub_byte(byte) | acc])

  @spec compute_round_constant(j :: pos_integer()) :: Aes.word()
  @spec compute_round_constant(j :: pos_integer(), acc :: non_neg_integer()) :: pos_integer()
  def compute_round_constant(j),
    do: <<compute_round_constant(j, 0x01)::8, 0x00::8, 0x00::8, 0x00::8>>

  defp compute_round_constant(1, acc), do: acc

  defp compute_round_constant(j, acc) when acc >= 0x80 do
    compute_round_constant(j - 1, Bitwise.bxor(0x11B, 0x02 * acc))
  end

  defp compute_round_constant(j, acc), do: compute_round_constant(j - 1, 0x02 * acc)

  @spec bxor_words(word_a :: Aes.word(), word_b :: Aes.word()) :: Aes.word()
  defp bxor_words(word_a, word_b), do: word_a |> bxor_words(word_b, []) |> byte_list_to_word()

  @spec bxor_words(word_a :: binary(), word_b :: binary(), acc :: list(byte())) :: [byte(), ...]
  defp bxor_words(<<>>, <<>>, acc), do: acc

  defp bxor_words(<<a::8, a_rest::binary>>, <<b::8, b_rest::binary>>, acc) do
    bxor_words(a_rest, b_rest, acc ++ [Bitwise.bxor(a, b)])
  end

  @spec g_function(word :: Aes.word(), round :: pos_integer()) :: Aes.word()
  defp g_function(word, round) do
    round_constant = compute_round_constant(round)

    word
    # |> util_now("      word")
    |> one_byte_left_rotate()
    # |> util_now("    rotate")
    |> sub_word()
    # |> util_now("  sub_word")
    |> bxor_words(round_constant)
    # |> util_now("bxor_words")
  end

  defp util_now(<<a::8, b::8, c::8, d::8>> = word, label) do
    [a, b, c, d]
    |> Enum.map(&Integer.to_string(&1, 16))
    |> (fn [a, b, c, d] -> "(#{a}, #{b}, #{c}, #{d})" end).()
    |> IO.inspect(label: label)

    word
  end

  @spec sub_byte(byte :: non_neg_integer()) :: non_neg_integer()
  defp sub_byte(byte), do: Table.get_at(byte)

  defp binary_to_word_list(binary), do: binary |> binary_to_word_list([]) |> Enum.reverse()

  defp binary_to_word_list(<<word::32, r::binary>>, acc),
    do: binary_to_word_list(r, [<<word::32>> | acc])

  defp binary_to_word_list(<<>>, acc), do: acc

  @spec multiple_words_to_byte_lists(binary :: <<_::_*4>>) :: [[non_neg_integer(), ...], ...]
  @spec multiple_words_to_byte_lists(
          binary :: <<_::_*4>>,
          acc :: [] | [[non_neg_integer(), ...], ...]
        ) :: [[non_neg_integer(), ...], ...]
  defp multiple_words_to_byte_lists(binary),
    do: binary |> multiple_words_to_byte_lists([]) |> Enum.reverse()

  defp multiple_words_to_byte_lists(<<>>, acc), do: acc

  defp multiple_words_to_byte_lists(<<word::32, rest::binary>>, acc) do
    <<word::32>> |> word_to_byte_list() |> then(&multiple_words_to_byte_lists(rest, [&1 | acc]))
  end

  @spec word_to_byte_list(word :: Aes.word()) :: [non_neg_integer(), ...]
  defp word_to_byte_list(<<a::8, b::8, c::8, d::8>>), do: [a, b, c, d]

  @spec byte_list_to_word(byte_list :: [non_neg_integer(), ...]) :: Aes.word()
  defp byte_list_to_word([a, b, c, d]), do: <<a::8, b::8, c::8, d::8>>
end
