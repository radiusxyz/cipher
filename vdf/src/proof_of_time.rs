use super::classgroup::ClassGroup;
use std::collections::HashMap;

pub fn iterate_squarings<V, U>(mut x: V, powers_to_calculate: U) -> HashMap<u64, V>
where
  V: ClassGroup,
  for<'a, 'b> &'a V: std::ops::Mul<&'b V, Output = V>,
  for<'a, 'b> &'a V::BigNum: std::ops::Mul<&'b V::BigNum, Output = V::BigNum>,
  U: Iterator<Item = u64>,
{
  let mut powers_calculated = HashMap::new();
  let mut powers_to_calculate: Vec<u64> = powers_to_calculate.collect();

  // 정렬 함수
  powers_to_calculate.sort_unstable();

  let mut previous_power: u64 = 0;
  for &current_power in &powers_to_calculate {
    x.repeated_square(current_power - previous_power);
    powers_calculated.insert(current_power, x.clone());
    previous_power = current_power
  }

  powers_calculated
}
