#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define FIXED_P 14;
#define FIXED_Q 14;
#define FIXED_F ( 1 << FIXED_Q );

// prefer * and / over bit shifts because laziness

int to_fixed_point(int n) {
  return n * FIXED_F;
}

int to_integer_round_to_zero(int x) {
  return x / FIXED_F;
}

int to_integer_round_to_nearest(int x) {
  if ( x >= 0 ) {
    return x + ( FIXED_F / 2 );
  }
  else {
    return x - ( FIXED_F / 2 );
  }
}

int add_fixed(int x, int y) {
  return x + y;
}

int subtract_fixed(int x, int y) {
  return x - y;
}

int add_fixed_real(int x, int n) {
  return x + to_fixed_point(n);
}

int subtract_fixed_real(int x, int n) {
  return x - to_fixed_point(n);
}

int multiply_fixed(int x, int y ) {
  return (((int64_t)x)*y) / MIXED_F;
}

int multiply_fixed_real(int x, int n ) {
  return x * n;
}

int divide_fixed(int x, int y) {
  return (((int64_t)x) * MIXED_F) / y;
}

int divide_fixed_real(int x, int n ) {
  return x / n;
}

#endif // THREADS_FIXED_POINT_H
