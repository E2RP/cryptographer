defmodule Cryptographer.Aes do
  @type word_binary :: <<_::32>>
  @type word_byte_list :: [byte(), ...]
  @type word :: word_binary() | word_byte_list()

  @type words_binary :: <<_::_*32>>
  @type words_byte_list :: [word_byte_list(), ...]
  @type words :: words_binary() | words_byte_list()

  alias Cryptographer.Aes.{BinaryUtils, Key, SBox}
  alias Cryptographer.Aes.MatrixUtils, as: Matrix
  alias Cryptographer.Aes.Key.Scheduler

  @spec encrypt(message :: binary(), key :: Key.t()) :: binary()
  def encrypt(message, key) do
    expanded_key = Scheduler.expand_key(key)

    Enum.reduce(0..10, message, fn round, last_round_result ->
      round_key = Enum.at(expanded_key, round)
      do_round(round, last_round_result, round_key)
    end)
  end

  def round(n, m, r), do: do_round(n, m, r)

  defp do_round(0, message, round_key) do
    add_round_key(message, round_key)
  end

  defp do_round(10, message, round_key) do
    message
    |> add_round_key(round_key)
    |> sub_bytes()
    |> shift_rows()
  end

  defp do_round(_, message, round_key) do
    message
    |> IO.inspect(label: 1)
    |> sub_bytes()
    |> IO.inspect(label: 2)
    |> shift_rows()
    |> IO.inspect(label: 3)
    |> mix_columns()
    |> IO.inspect(label: 4)
    |> add_round_key(round_key)
    |> IO.inspect(label: 5)
  end

  defp add_round_key(message, round_key), do: BinaryUtils.bxor_binaries(message, round_key)
  defp sub_bytes(message), do: SBox.sub_word(message)

  defp shift_rows(message) do
    message
    |> IO.inspect(label: :message)
    |> BinaryUtils.multiple_words_to_byte_lists()
    |> IO.inspect(label: :multiple_words_to_byte_lists)
    |> Matrix.transpose()
    |> IO.inspect(label: :transpose)
    |> then(fn matrix ->
      matrix
      |> Enum.with_index()
      |> Enum.map(fn {row, i} ->
        Enum.reduce(0..(3 + i), row, fn _, shifted_row ->
          BinaryUtils.one_byte_left_rotate(shifted_row)
        end)
      end)
    end)
    |> IO.inspect(label: :shift)
    |> Matrix.transpose()
    |> IO.inspect(label: :transpose)
  end

  defp mix_columns(message) do
    Matrix.multiply([[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]], message)
  end
end
