# coding=utf8
import collections

__author__ = 'Alexander.Li'


# Modular arithmetic ##########################################################

# Alexander.Li: Next functions from https://github.com/andreacorbellini/ecc

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# Functions that work on curve points #########################################

def testBit(i, n):
    return i & (1<<n) != 0


def quick_algorithm(a, b, c): #y=a^b%c,a的b次幂余除c
   a = a % c
   ans = 1
   #这里我们不需要考虑b<0，因为分数没有取模运算
   while b != 0: #费马小定理
      if b & 1:
         ans = (ans * a) % c
      b>>=1
      a = (a * a) % c
   return ans

def is_have_mosqrt(x, P):#是否有模平方根y*y=x mod p，已知x，p，判断是否存在y
   ret = quick_algorithm(x,(P-1)//2,P)
   if ret==1:
      return True
   else:
      return False


def get_mosqrt(x, P):#求模平方根y*y=x mod p，已知x，p求y
   if(is_have_mosqrt(x, P)==1):
      t=0
      s=P-1#P-1=(2^t)*s //s是奇数
      while s%2==0:
         s=s//2
         t=t+1
      if(t==1):
         ret = quick_algorithm(x,(s+1)//2,P)
         return (ret, P-ret)
      elif (t>=2):
         x_=quick_algorithm(x,P-2,P)
         n=1
         while(is_have_mosqrt(n, P) == 1):
            n=n+1
         b=quick_algorithm(n,s,P)
         print(b)
         ret = quick_algorithm(x,(s+1)//2,P)#t-1
         t_=0
         while(t-1>0):
            if(quick_algorithm(x_*ret*ret,2**(t-2),P)==1):
               ret=ret
            else:
               ret=ret*(b**(2**t_))%P
            t=t-1
            t_=t_+1
         return (ret, P-ret)
      else:
         return (-2, -2)
   else:
      return (-1, -1)


def get_y_by_x(x, prefix):#y^2=x^3+7 (mod p)根据x求y
    a = (x*x*x+7) % curve.p
    ret = get_mosqrt(a, curve.p)
    if prefix == '02':
        for y in ret:
            if not testBit(y, 0):
                return y
    if prefix == '03':
        for y in ret:
            if testBit(y, 0):
                return y
    return None


def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point
    rs = (y * y - x * x * x - curve.a * x - curve.b) % curve.p
    return rs == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add. 如果是奇数就加一下
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result