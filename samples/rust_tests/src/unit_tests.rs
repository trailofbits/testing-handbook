#[cfg(test)]
mod unit_tests {
    #[test]
    fn true_dilemma() {
        assert_ne!(true, false);
    }

    /* Randomization */
    #[cfg(test)]
    mod tests2 {
        use crate::{GLOB_VAR, global_var_set};

        #[test]
        fn a_true_dilemma() {
            unsafe { assert_eq!(GLOB_VAR, 2); }
            unsafe { global_var_set(5); }
            unsafe { assert_eq!(GLOB_VAR, 5); }
            assert_ne!(true, false);
        }

        #[test]
        fn not_true_dilemma() {
            unsafe { assert_eq!(GLOB_VAR, 2); }
            assert_ne!(true, false);
        }
    }

    #[cfg(test)]
    mod tests3 {
        use crate::{feature_one};

        #[test]
        fn feature_test1() {
            let z = feature_one();
            assert!(z < 3);
        }
    }
    /* END Randomization */

    /* Integer overflows */
    #[cfg(test)]
    #[allow(unused_variables)]
    mod tests4 {
        use crate::{overflow_lib::as_u16, overflow_lib::do_overflow};

        #[should_panic]
        #[test]
        fn int_overflow_simple() {
            let y_str = "2147483647";
            let y = y_str.parse::<i32>().unwrap();
            let x = do_overflow(y);
        }

        #[should_panic]
        #[test]
        fn int_overflow_in_cast() {
            let y_str = "2147483647";
            let y = y_str.parse::<i32>().unwrap();
            println!("{}", y);
            let a = as_u16(y);
        }
    }
    /* END Integer overflows */

    /* Sanitizers */
    #[cfg(test)]
    #[allow(unused_variables)]
    mod tests5 {
        #[test]
        fn uaf() {
            let a = vec![7, 3, 3, 1];
            let b = a.as_ptr();
            drop(a);
            let z = unsafe { *b };
        }
    }
    /* END Sanitizers */

    /* Miri */
    #[cfg(test)]
    mod tests_miri {
        fn x() {}

        #[test]
        fn miri_example() {
            let f = x as *const usize;
            let y = unsafe {
                *f.map_addr(|a| a + 8)
            };
            assert_eq!(y, 0x841f0f);
        }
    }
    /* END Miri */

    /* Proptest */
    #[cfg(test)]
    mod tests6 {
        use crate::simple_thingy_dingy;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(100))]
            #[test]
            fn test_simple_thingy_dingy(a in 1337..7331u64, b in "[0-9]{1,3}") {
                println!("{a} | {b}");
                let sum = simple_thingy_dingy(a, &b);
                assert!(sum >= a);
                assert!(sum > 1337);
            }
        }
    }
    /* END Proptest */

    /* Necessist */
    #[cfg(test)]
    mod tests7 {
        use crate::{Data, validate_data};

        #[test]
        fn parser_detects_errors() {
            let mut blob = Data{
                magic: [0x73, 0x31],
                len: 2,
                content: "AB".parse().unwrap(),
            };
            blob.content = blob.content + "Y";
            let result = validate_data(&blob);
            assert!(result.is_err());
        }
    }
    /* END Necessist */
}


