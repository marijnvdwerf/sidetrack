
class Emu {

 public:
  // Push Word, Doubleword or Quadword Onto the Stack
  constexpr void push(uint32_t arg) {
      esp -= 4;
      mem<uint32_t>(esp) = arg;
  }

  // Pop a Value from the Stack
  constexpr uint32_t pop() {
      uint32_t retval = mem<uint32_t>(esp);
      esp += 4;

      return retval;
  }

  // Double Precision Shift Right
  void shrd(uint32_t *arg, uint32_t arg2, uint8_t imm) {
      if (imm == 0)
          return;

      if (imm > 32) {
          // bad parameters
          return;
      }
  }

  // Unsigned divide r/m32 by 2, count times.
  void shr(uint32_t *destination, uint8_t count) {

      while (count != 0) {
          cf = LSB(*destination);
          *destination = *destination / 2;
          count--;
      }
  }

  // Unsigned Multiply
  // https://c9x.me/x86/html/file_module_x86_id_210.html
  // FIXME: u8, u16, u32
  void mul(uint32_t arg) {

  }

  // Unsigned Divide
  // https://c9x.me/x86/html/file_module_x86_id_72.html
  // Unsigned divide EDX:EAX by r/m32, with result stored in EAX = Quotient, EDX = Remainder.
  // The CF, OF, SF, ZF, AF, and PF flags are undefined.
  constexpr void div(uint32_t divisor) {
      uint64_t dividend = edx;
      dividend = (dividend << 32) | eax;

      eax = dividend / divisor;
      edx = dividend % divisor;
  }

  uint32_t eax;
  uint32_t ecx;
  uint32_t edx;
  uint32_t esp;

  uint8_t cf:1;
};
