(module
  ;; Suspicious plugin with crypto-like patterns
  (memory 1)
  
  (func $crypto_loop (param i64) (result i64)
    (local i64 i64)
    (local.set 1 (local.get 0))
    (local.set 2 (i64.const 0))
    
    ;; Simulate crypto mining patterns
    (loop $mining_loop
      (local.set 2 (i64.add (local.get 2) (i64.const 1)))
      (local.set 1 (i64.mul (local.get 1) (i64.const 1103515245)))
      (local.set 1 (i64.add (local.get 1) (i64.const 12345)))
      (local.set 1 (i64.rem_u (local.get 1) (i64.const 2147483648)))
      
      ;; More crypto operations
      (local.set 1 (i64.xor (local.get 1) (i64.const 0xFFFFFFFF)))
      (local.set 1 (i64.and (local.get 1) (i64.const 0x7FFFFFFF)))
      
      ;; Memory operations
      (i32.store (i32.const 0) (i32.wrap_i64 (local.get 1)))
      (local.set 1 (i64.extend_i32_u (i32.load (i32.const 0))))
      
      ;; Complex control flow
      (br_if $mining_loop (i64.lt_s (local.get 2) (local.get 0)))
    
    (local.get 1)
  )
  
  (func $suspicious_function (export "run") (param i32) (result i32)
    (local i64)
    (local.set 0 (i64.extend_i32_u (local.get 0)))
    (call $crypto_loop (local.get 0))
    (i32.wrap_i64)
  )
) 