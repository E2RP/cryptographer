defmodule Cryptographer.Aes.MatrixUtils do
  alias Cryptographer.Aes.RijndaelGaloisField, as: GF

  def transpose(matrix), do: matrix |> Enum.zip() |> Enum.map(&Tuple.to_list/1)

  def multiply(matrix_a, matrix_b) do
    Enum.map(matrix_a, fn i ->
      matrix_b
      |> transpose()
      |> Enum.map(fn j ->
        i
        |> Enum.zip(j)
        # |> Enum.map(fn {i, j} ->
        #   IO.inspect("#{i} * #{j} = #{i * j}")
        #   i * j
        # end)
        |> tap(fn a ->
          a
          |> Enum.map(fn {i, j} -> "#{i} * #{j}" end)
          |> Enum.join(" xor ")
          |> IO.inspect(label: :line)
        end)
        |> Enum.reduce(fn {i, j}, acc ->
          case acc do
            {a, b} -> GF.multiply(a, b)
            acc -> GF.add(i * j, acc)
          end
        end)
      end)
    end)
  end
end
