#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 29 2023

@author: iluzioDev

This script implements Diffie-Hellman algorithm.
"""
from colorama import Fore

ROW = '■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■'
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

"""Check if a number is prime or not.
"""
def check_prime(n): return all(n % i for i in range(2, n))

def fast_exponentiation(base, exponent, modulus):
  """Fast exponentiation algorithm.

  Args:
      base (int): Base number.
      exponent (int): Exponent number.
      modulus (int): Modulus number.
  """
  base = int(base)
  exponent = int(exponent)
  modulus = int(modulus)

  result = 1
  base = base % modulus
  while exponent > 0 and base > 1:
    if exponent % 2 == 1:
      result = (result * base) % modulus
      exponent = exponent - 1
    else:
      base = (base * base) % modulus
      exponent = exponent / 2
  return result

def diffie_hellman(p, alpha, secrets):
  """Diffie-Hellman algorithm for two or more users.

  Args:
      p (int): Prime number.
      alpha (int): Primitive root of p.
      xA (int): Secret number of A.
      xB (int): Secret number of B.

  Returns:
      int: Shared secret key.
  """
  p = int(p)
  alpha = int(alpha)

  aux = {}
  for i in range(len(secrets)):
    aux[alphabet[i]] = int(secrets[i])
  secrets = aux

  if check_prime(p) is False or alpha > p:
    return None

  if len(secrets) < 2:
    return None

  letters = []
  for i in range(len(secrets)):
    letters.append(alphabet[i])

  y = {}
  for i in range(len(secrets)):
    y[letters[i]] = fast_exponentiation(alpha, secrets[letters[i]], p)

  shared_keys = {}
  for i in range(len(secrets)):
    shared_keys[letters[i]] = secrets[letters[i]]

  for i in range(0, len(secrets) - 1):
    if i == 0:
      for j in range(len(secrets)):
        shared_keys[letters[j] + letters[(j + 1) % len(secrets)]] = fast_exponentiation(
            y[letters[j]], shared_keys[letters[(j + 1) % len(secrets)]], p)
    else:
      for j in range(len(secrets)):
        if (len(shared_keys)) != len(secrets) * (i + 2):
          k = (j + i + 1) % len(secrets)
          rest_letters = ""
          if j + i + 2 > len(secrets):
            rest_letters = "".join(letters[j + 1: len(secrets)])
            rest_letters += "".join(letters[0: i + 1 - len(rest_letters)])
          else:
            rest_letters = "".join(letters[j + 1: (k + 1)])
          index = letters[j] + rest_letters
          
          old_index = ""
          for l in range(len(shared_keys)):
            if sorted(rest_letters) == sorted(list(shared_keys.keys())[l]):
              old_index = list(shared_keys.keys())[l]
              break
          if old_index != "":
            shared_keys[index] = fast_exponentiation(
                shared_keys[old_index], shared_keys[letters[j]], p)

  for i in range(len(secrets)):
    del shared_keys[letters[i]]

  return y, shared_keys

def main():
  """Main function of the script.
  """
  while (True):
    print(ROW)
    print('■                   WELCOME TO THE CBC MODE TOOL!                    ■')
    print(ROW)
    print('What do you want to do?')
    print('[1] Generate secret keys.')
    print('[0] Exit.')
    print(ROW)
    option = input('Option  ->  ')
    print(ROW)

    if int(option) not in range(3):
      print('Invalid option!')

    if option == '0':
      print('See you soon!')
      print(ROW)
      break

    if option == '1':
      num_users = input('Enter the number of users (more than 1)  ->  ')
      print(ROW)
      if not num_users.isnumeric() or int(num_users) < 2:
        print('Invalid number of users!')
        continue

      prime_number = input('Enter a prime number  ->  ')
      print(ROW)
      if not prime_number.isnumeric() or check_prime(int(prime_number)) is False:
        print('Invalid prime number!')
        continue

      alpha = input('Enter a primitive root of the prime number  ->  ')
      print(ROW)
      if int(alpha) > int(prime_number):
        print('Invalid primitive root!')
        break

      users = []
      for i in range(int(num_users)):
        users.append(input(f'Enter the secret key of user {i + 1}  ->  '))
        if int(users[i]) < 0:
          users = []
          print(ROW)
          print(Fore.RED + 'The secret key must be a positive number!' + Fore.RESET)
          break
        print(ROW)

      if len(users) == 0:
        continue

      y, shared_keys = diffie_hellman(prime_number, alpha, users)
      for i in range(len(y)):
        print(f'y{list(y.keys())[i]}: {y[list(y.keys())[i]]}')
      print(ROW)
      iteration = 0
      for i in range(len(shared_keys)):
        print(
            f'k{list(shared_keys.keys())[i]}: {shared_keys[list(shared_keys.keys())[i]]}')
        iteration += 1
        if iteration == len(users):
          if i != len(shared_keys) - 1:
            print(ROW)
          iteration = 0
      l = list(shared_keys.keys())
      shared_key = shared_keys[list(shared_keys.keys())[-1]]
      print(ROW)
      print(Fore.YELLOW + 'Shared secret key: ' + str(shared_key) + Fore.RESET)

  return


if __name__ == '__main__':
  main()
