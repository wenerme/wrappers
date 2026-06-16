use crate::prelude::*;
use pgrx::pg_sys::Oid;
use pgrx::{
    FromDatum, PgBuiltInOids, PgOid,
    datum::{Array, Date, JsonB, Timestamp},
    is_a,
    list::List,
    pg_sys,
    pg_sys::Datum,
};
use std::ffi::CStr;
use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr;
use std::sync::Mutex;

use crate::interface::Param;

// create array of Cell from constant datum array
pub(crate) unsafe fn form_array_from_datum(
    datum: Datum,
    is_null: bool,
    typoid: pg_sys::Oid,
) -> Option<Vec<Cell>> {
    let oid = PgOid::from(typoid);
    match oid {
        PgOid::BuiltIn(PgBuiltInOids::BOOLARRAYOID) => {
            unsafe { Array::<bool>::from_polymorphic_datum(datum, is_null, pg_sys::BOOLOID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::Bool(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        PgOid::BuiltIn(PgBuiltInOids::CHARARRAYOID) => {
            unsafe { Array::<i8>::from_polymorphic_datum(datum, is_null, pg_sys::CHAROID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::I8(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        PgOid::BuiltIn(PgBuiltInOids::INT2ARRAYOID) => {
            unsafe { Array::<i16>::from_polymorphic_datum(datum, is_null, pg_sys::INT2OID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::I16(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        PgOid::BuiltIn(PgBuiltInOids::FLOAT4ARRAYOID) => {
            unsafe { Array::<f32>::from_polymorphic_datum(datum, is_null, pg_sys::FLOAT4OID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::F32(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        PgOid::BuiltIn(PgBuiltInOids::INT4ARRAYOID) => {
            unsafe { Array::<i32>::from_polymorphic_datum(datum, is_null, pg_sys::INT4OID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::I32(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        PgOid::BuiltIn(PgBuiltInOids::FLOAT8ARRAYOID) => {
            unsafe { Array::<f64>::from_polymorphic_datum(datum, is_null, pg_sys::FLOAT8OID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::F64(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        PgOid::BuiltIn(PgBuiltInOids::INT8ARRAYOID) => {
            unsafe { Array::<i64>::from_polymorphic_datum(datum, is_null, pg_sys::INT8OID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::I64(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        PgOid::BuiltIn(PgBuiltInOids::TEXTARRAYOID) => {
            unsafe { Array::<String>::from_polymorphic_datum(datum, is_null, pg_sys::TEXTOID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::String(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        PgOid::BuiltIn(PgBuiltInOids::DATEARRAYOID) => {
            unsafe { Array::<Date>::from_polymorphic_datum(datum, is_null, pg_sys::DATEOID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::Date(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        PgOid::BuiltIn(PgBuiltInOids::TIMESTAMPARRAYOID) => unsafe {
            Array::<Timestamp>::from_polymorphic_datum(datum, is_null, pg_sys::TIMESTAMPOID)
        }
        .map(|arr| {
            arr.iter()
                .filter(|v| v.is_some())
                .map(|v| Cell::Timestamp(v.expect("non-null array element")))
                .collect::<Vec<_>>()
        }),
        PgOid::BuiltIn(PgBuiltInOids::JSONBARRAYOID) => {
            unsafe { Array::<JsonB>::from_polymorphic_datum(datum, is_null, pg_sys::JSONBOID) }.map(
                |arr| {
                    arr.iter()
                        .filter(|v| v.is_some())
                        .map(|v| Cell::Json(v.expect("non-null array element")))
                        .collect::<Vec<_>>()
                },
            )
        }
        _ => None,
    }
}

/// Try to evaluate a non-Const, non-Param expression to a Cell value at
/// planning time. This handles stable/immutable expressions like
/// `now() - interval '1 hour'` by asking PostgreSQL to evaluate them.
///
/// # Safety
///
/// `expr` must be a valid expression node pointer.
unsafe fn try_eval_const_expr(expr: *mut pg_sys::Node) -> Option<Cell> {
    unsafe {
        // Use eval_const_expressions to try to simplify the expression.
        // This will fold stable functions (like now()) that are safe to
        // evaluate at planning time.
        let simplified = pg_sys::eval_const_expressions(ptr::null_mut(), expr);
        if simplified.is_null() {
            return None;
        }

        // If it simplified to a Const, extract the value
        if is_a(simplified, pg_sys::NodeTag::T_Const) {
            let cst = simplified as *mut pg_sys::Const;
            return Cell::from_polymorphic_datum(
                (*cst).constvalue,
                (*cst).constisnull,
                (*cst).consttype,
            );
        }

        // If not fully reduced to Const, try direct evaluation via the executor.
        // This handles cases like now() which is stable within a transaction.
        let expr_type = pg_sys::exprType(expr);
        let expr_typmod = pg_sys::exprTypmod(expr);

        // Build a simple expression evaluation to get the result
        let estate = pg_sys::CreateExecutorState();
        if estate.is_null() {
            return None;
        }

        let expr_state = pg_sys::ExecInitExpr(expr as *mut pg_sys::Expr, ptr::null_mut());
        if expr_state.is_null() {
            pg_sys::FreeExecutorState(estate);
            return None;
        }

        let econtext = pg_sys::MakePerTupleExprContext(estate);
        let mut is_null = false;
        let datum = pg_sys::ExecEvalExprSwitchContext(expr_state, econtext, &mut is_null);

        let result = if is_null {
            None
        } else {
            Cell::from_polymorphic_datum(datum, false, expr_type)
        };

        pg_sys::FreeExecutorState(estate);
        let _ = expr_typmod; // suppress unused warning

        result
    }
}

/// Try to extract a JSONB sub-field qual from `(col->>'key') op const`.
///
/// Returns a Qual with field = "col.key" if successful, so FDWs can
/// distinguish jsonb sub-field conditions from top-level column conditions.
///
/// # Safety
///
/// `left` must be a valid OpExpr node, `right` must be a valid Const node.
unsafe fn try_extract_jsonb_qual(
    baserel_id: pg_sys::Oid,
    baserel_ids: pg_sys::Relids,
    left: *mut pg_sys::OpExpr,
    right: *mut pg_sys::Const,
    outer_op_name: &pgrx::pg_sys::nameData,
) -> Option<Qual> {
    unsafe {
        pgrx::memcx::current_context(|mcx| {
            let inner_args = List::<*mut c_void>::downcast_ptr_in_memcx((*left).args, mcx)?;
            if inner_args.len() != 2 {
                return None;
            }

            let inner_left = unnest_clause(*inner_args.get(0)? as _);
            let inner_right = unnest_clause(*inner_args.get(1)? as _);

            // Require: inner_left is a Var (jsonb/json column)
            if !is_a(inner_left, pg_sys::NodeTag::T_Var) {
                return None;
            }
            // Require: inner_right is a text Const (the key)
            if !is_a(inner_right, pg_sys::NodeTag::T_Const) {
                return None;
            }

            let inner_var = inner_left as *mut pg_sys::Var;
            if !pg_sys::bms_is_member((*inner_var).varno as c_int, baserel_ids)
                || (*inner_var).varattno < 1
            {
                return None;
            }

            // Check operator name is ->> (text extraction) or -> (json)
            let inner_opr = get_operator((*left).opno);
            if inner_opr.is_null() {
                return None;
            }
            let inner_op_name = pgrx::name_data_to_str(&(*inner_opr).oprname);
            if inner_op_name != "->>" && inner_op_name != "->" {
                return None;
            }

            // Extract the JSONB key from inner_right (text datum = varlena)
            let key_const = inner_right as *mut pg_sys::Const;
            let key = String::from_datum((*key_const).constvalue, (*key_const).constisnull)?;

            // Extract the outer value from right (the comparison value)
            let value = Cell::from_polymorphic_datum(
                (*right).constvalue,
                (*right).constisnull,
                (*right).consttype,
            )?;

            // Get the column name
            let col_name = pg_sys::get_attname(baserel_id, (*inner_var).varattno, false);
            let col_name_str = std::ffi::CStr::from_ptr(col_name).to_str().ok()?;

            // Encode as "col.key" so FDWs can detect JSONB sub-field conditions
            let field = format!("{col_name_str}.{key}");
            let operator = pgrx::name_data_to_str(outer_op_name).to_string();

            Some(Qual {
                field,
                operator,
                value: Value::Cell(value),
                use_or: false,
                param: None,
            })
        })
    }
}

pub(crate) unsafe fn get_operator(opno: pg_sys::Oid) -> pg_sys::Form_pg_operator {
    unsafe {
        let htup = pg_sys::SearchSysCache1(
            pg_sys::SysCacheIdentifier::OPEROID.try_into().unwrap(),
            opno.into(),
        );
        if htup.is_null() {
            pg_sys::ReleaseSysCache(htup);
            pgrx::error!("cache lookup operator {:?} failed", opno);
        }
        let op = pg_sys::GETSTRUCT(htup) as pg_sys::Form_pg_operator;
        pg_sys::ReleaseSysCache(htup);
        op
    }
}

pub(crate) unsafe fn unnest_clause(node: *mut pg_sys::Node) -> *mut pg_sys::Node {
    unsafe {
        if is_a(node, pg_sys::NodeTag::T_RelabelType) {
            (*(node as *mut pg_sys::RelabelType)).arg as _
        } else if is_a(node, pg_sys::NodeTag::T_ArrayCoerceExpr) {
            (*(node as *mut pg_sys::ArrayCoerceExpr)).arg as _
        } else {
            node
        }
    }
}

pub(crate) unsafe fn extract_from_op_expr(
    _root: *mut pg_sys::PlannerInfo,
    baserel_id: pg_sys::Oid,
    baserel_ids: pg_sys::Relids,
    expr: *mut pg_sys::OpExpr,
) -> Option<Qual> {
    unsafe {
        pgrx::memcx::current_context(|mcx| {
            if let Some(args) = List::<*mut c_void>::downcast_ptr_in_memcx((*expr).args, mcx) {
                // only deal with binary operator
                if args.len() != 2 {
                    report_warning("only support binary operator expression");
                    return None;
                }

                // get operator
                let opno = (*expr).opno;
                let opr = get_operator(opno);
                if opr.is_null() {
                    report_warning("operator is empty");
                    return None;
                }

                let mut left = unnest_clause(*args.get(0).unwrap() as _);
                let mut right = unnest_clause(*args.get(1).unwrap() as _);

                // swap operands if needed
                if is_a(right, pg_sys::NodeTag::T_Var)
                    && !is_a(left, pg_sys::NodeTag::T_Var)
                    && (*opr).oprcom != Oid::INVALID
                {
                    std::mem::swap(&mut left, &mut right);
                }

                // Handle jsonb extraction: (col->>'key') op const
                // Produces field = "col.key" so FDWs can recognize JSONB sub-field quals.
                if is_a(left, pg_sys::NodeTag::T_OpExpr)
                    && is_a(right, pg_sys::NodeTag::T_Const)
                    && let Some(jsonb_qual) = try_extract_jsonb_qual(
                        baserel_id,
                        baserel_ids,
                        left as _,
                        right as _,
                        &(*opr).oprname,
                    )
                {
                    return Some(jsonb_qual);
                }

                if is_a(left, pg_sys::NodeTag::T_Var) {
                    let left = left as *mut pg_sys::Var;

                    if pg_sys::bms_is_member((*left).varno as c_int, baserel_ids)
                        && (*left).varattno >= 1
                    {
                        let field = pg_sys::get_attname(baserel_id, (*left).varattno, false);

                        let (value, param) = if is_a(right, pg_sys::NodeTag::T_Const) {
                            let right = right as *mut pg_sys::Const;
                            (
                                Cell::from_polymorphic_datum(
                                    (*right).constvalue,
                                    (*right).constisnull,
                                    (*right).consttype,
                                ),
                                None,
                            )
                        } else if is_a(right, pg_sys::NodeTag::T_Param) {
                            // add a dummy value if this is query parameter, the actual value
                            // will be extracted from execution state
                            let right = right as *mut pg_sys::Param;
                            let param = Param {
                                kind: (*right).paramkind,
                                id: (*right).paramid as _,
                                type_oid: (*right).paramtype,
                                eval_value: Mutex::new(None).into(),
                                expr_eval: ExprEval {
                                    expr: if (*right).paramkind == pg_sys::ParamKind::PARAM_EXEC {
                                        right as _
                                    } else {
                                        ptr::null_mut()
                                    },
                                    expr_state: ptr::null_mut(),
                                },
                            };
                            (Some(Cell::I64(0)), Some(param))
                        } else if let Some(cell) = try_eval_const_expr(right) {
                            // Try to evaluate stable/immutable expressions
                            // like now() - interval '1 hour' to a constant
                            (Some(cell), None)
                        } else {
                            (None, None)
                        };

                        if let Some(value) = value {
                            let qual = Qual {
                                field: CStr::from_ptr(field).to_str().unwrap().to_string(),
                                operator: pgrx::name_data_to_str(&(*opr).oprname).to_string(),
                                value: Value::Cell(value),
                                use_or: false,
                                param,
                            };
                            return Some(qual);
                        }
                    }
                }

                if let Some(stm) = pgrx::nodes::node_to_string(expr as _) {
                    report_warning(&format!("unsupported operator expression in qual: {stm}",));
                }
            }

            None
        })
    }
}

pub(crate) unsafe fn extract_from_null_test(
    baserel_id: pg_sys::Oid,
    expr: *mut pg_sys::NullTest,
) -> Option<Qual> {
    unsafe {
        let var = (*expr).arg as *mut pg_sys::Var;
        if !is_a(var as _, pg_sys::NodeTag::T_Var) || (*var).varattno < 1 {
            return None;
        }

        let field = pg_sys::get_attname(baserel_id, (*var).varattno, false);

        let opname = if (*expr).nulltesttype == pg_sys::NullTestType::IS_NULL {
            "is".to_string()
        } else {
            "is not".to_string()
        };

        let qual = Qual {
            field: CStr::from_ptr(field).to_str().unwrap().to_string(),
            operator: opname,
            value: Value::Cell(Cell::String("null".to_string())),
            use_or: false,
            param: None,
        };

        Some(qual)
    }
}

pub(crate) unsafe fn extract_from_scalar_array_op_expr(
    _root: *mut pg_sys::PlannerInfo,
    baserel_id: pg_sys::Oid,
    baserel_ids: pg_sys::Relids,
    expr: *mut pg_sys::ScalarArrayOpExpr,
) -> Option<Qual> {
    unsafe {
        pgrx::memcx::current_context(|mcx| {
            if let Some(args) = List::<*mut c_void>::downcast_ptr_in_memcx((*expr).args, mcx) {
                // only deal with binary operator
                if args.len() != 2 {
                    return None;
                }

                // get operator
                let opno = (*expr).opno;
                let opr = get_operator(opno);
                if opr.is_null() {
                    return None;
                }

                let left = unnest_clause(*args.get(0).unwrap() as _);
                let right = unnest_clause(*args.get(1).unwrap() as _);

                if is_a(left, pg_sys::NodeTag::T_Var) && is_a(right, pg_sys::NodeTag::T_Const) {
                    let left = left as *mut pg_sys::Var;
                    let right = right as *mut pg_sys::Const;

                    if pg_sys::bms_is_member((*left).varno as c_int, baserel_ids)
                        && (*left).varattno >= 1
                    {
                        let field = pg_sys::get_attname(baserel_id, (*left).varattno, false);

                        let value: Option<Vec<Cell>> = form_array_from_datum(
                            (*right).constvalue,
                            (*right).constisnull,
                            (*right).consttype,
                        );
                        if let Some(value) = value {
                            let qual = Qual {
                                field: CStr::from_ptr(field).to_str().unwrap().to_string(),
                                operator: pgrx::name_data_to_str(&(*opr).oprname).to_string(),
                                value: Value::Array(value),
                                use_or: (*expr).useOr,
                                param: None,
                            };
                            return Some(qual);
                        }
                    }
                }

                if let Some(stm) = pgrx::nodes::node_to_string(expr as _) {
                    report_warning(&format!("only support const scalar array in qual: {stm}",));
                }
            }

            None
        })
    }
}

pub(crate) unsafe fn extract_from_var(
    _root: *mut pg_sys::PlannerInfo,
    baserel_id: pg_sys::Oid,
    baserel_ids: pg_sys::Relids,
    var: *mut pg_sys::Var,
) -> Option<Qual> {
    unsafe {
        if (*var).varattno < 1
            || (*var).vartype != pg_sys::BOOLOID
            || !pg_sys::bms_is_member((*var).varno as c_int, baserel_ids)
        {
            return None;
        }

        let field = pg_sys::get_attname(baserel_id, (*var).varattno, false);

        let qual = Qual {
            field: CStr::from_ptr(field).to_str().unwrap().to_string(),
            operator: "=".to_string(),
            value: Value::Cell(Cell::Bool(true)),
            use_or: false,
            param: None,
        };

        Some(qual)
    }
}

pub(crate) unsafe fn extract_from_bool_expr(
    _root: *mut pg_sys::PlannerInfo,
    baserel_id: pg_sys::Oid,
    baserel_ids: pg_sys::Relids,
    expr: *mut pg_sys::BoolExpr,
) -> Option<Qual> {
    unsafe {
        pgrx::memcx::current_context(|mcx| {
            if let Some(args) = List::<*mut c_void>::downcast_ptr_in_memcx((*expr).args, mcx) {
                if (*expr).boolop != pg_sys::BoolExprType::NOT_EXPR || args.len() != 1 {
                    return None;
                }

                let var = *args.get(0).unwrap() as *mut pg_sys::Var;
                if (*var).varattno < 1
                    || (*var).vartype != pg_sys::BOOLOID
                    || !pg_sys::bms_is_member((*var).varno as c_int, baserel_ids)
                {
                    return None;
                }

                let field = pg_sys::get_attname(baserel_id, (*var).varattno, false);

                let qual = Qual {
                    field: CStr::from_ptr(field).to_str().unwrap().to_string(),
                    operator: "=".to_string(),
                    value: Value::Cell(Cell::Bool(false)),
                    use_or: false,
                    param: None,
                };

                return Some(qual);
            }

            None
        })
    }
}

pub(crate) unsafe fn extract_from_boolean_test(
    baserel_id: pg_sys::Oid,
    expr: *mut pg_sys::BooleanTest,
) -> Option<Qual> {
    unsafe {
        let var = (*expr).arg as *mut pg_sys::Var;
        if !is_a(var as _, pg_sys::NodeTag::T_Var) || (*var).varattno < 1 {
            return None;
        }

        let field = pg_sys::get_attname(baserel_id, (*var).varattno, false);

        let (opname, value) = match (*expr).booltesttype {
            pg_sys::BoolTestType::IS_TRUE => ("is".to_string(), true),
            pg_sys::BoolTestType::IS_FALSE => ("is".to_string(), false),
            pg_sys::BoolTestType::IS_NOT_TRUE => ("is not".to_string(), true),
            pg_sys::BoolTestType::IS_NOT_FALSE => ("is not".to_string(), false),
            _ => return None,
        };

        let qual = Qual {
            field: CStr::from_ptr(field).to_str().unwrap().to_string(),
            operator: opname,
            value: Value::Cell(Cell::Bool(value)),
            use_or: false,
            param: None,
        };

        Some(qual)
    }
}

pub(crate) unsafe fn extract_quals(
    root: *mut pg_sys::PlannerInfo,
    baserel: *mut pg_sys::RelOptInfo,
    baserel_id: pg_sys::Oid,
) -> Vec<Qual> {
    unsafe {
        pgrx::memcx::current_context(|mcx| {
            let mut quals = Vec::new();

            if let Some(conds) =
                List::<*mut c_void>::downcast_ptr_in_memcx((*baserel).baserestrictinfo, mcx)
            {
                for cond in conds.iter() {
                    let expr = (*(*cond as *mut pg_sys::RestrictInfo)).clause as *mut pg_sys::Node;
                    let extracted = if is_a(expr, pg_sys::NodeTag::T_OpExpr) {
                        extract_from_op_expr(root, baserel_id, (*baserel).relids, expr as _)
                    } else if is_a(expr, pg_sys::NodeTag::T_NullTest) {
                        extract_from_null_test(baserel_id, expr as _)
                    } else if is_a(expr, pg_sys::NodeTag::T_ScalarArrayOpExpr) {
                        extract_from_scalar_array_op_expr(
                            root,
                            baserel_id,
                            (*baserel).relids,
                            expr as _,
                        )
                    } else if is_a(expr, pg_sys::NodeTag::T_Var) {
                        extract_from_var(root, baserel_id, (*baserel).relids, expr as _)
                    } else if is_a(expr, pg_sys::NodeTag::T_BoolExpr) {
                        extract_from_bool_expr(root, baserel_id, (*baserel).relids, expr as _)
                    } else if is_a(expr, pg_sys::NodeTag::T_BooleanTest) {
                        extract_from_boolean_test(baserel_id, expr as _)
                    } else {
                        if let Some(stm) = pgrx::nodes::node_to_string(expr) {
                            report_warning(&format!("unsupported qual: {stm}",));
                        }
                        None
                    };

                    if let Some(qual) = extracted {
                        quals.push(qual);
                    }
                }
            }

            quals
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(feature = "pg_test", pgrx_embed))]
    use pgrx::IntoDatum;

    #[cfg(all(feature = "pg_test", pgrx_embed))]
    #[test]
    fn test_form_array_from_datum_int4_array() {
        let values = vec![1_i32, 2_i32, 3_i32];
        let datum = values
            .into_datum()
            .expect("int4 array datum should be created");

        let result = unsafe { form_array_from_datum(datum, false, pg_sys::INT4ARRAYOID) };
        let result = result.expect("int4 array should be parsed");

        assert_eq!(result.len(), 3);
        assert!(matches!(result[0], Cell::I32(1)));
        assert!(matches!(result[1], Cell::I32(2)));
        assert!(matches!(result[2], Cell::I32(3)));
    }

    #[test]
    fn test_form_array_from_datum_null_datum_returns_none() {
        let result = unsafe { form_array_from_datum(0.into(), true, pg_sys::INT4ARRAYOID) };
        assert!(result.is_none());
    }

    #[cfg(all(feature = "pg_test", pgrx_embed))]
    #[test]
    fn test_form_array_from_datum_unsupported_oid_returns_none() {
        let values = vec![1_i32, 2_i32];
        let datum = values
            .into_datum()
            .expect("int4 array datum should be created");

        let result = unsafe { form_array_from_datum(datum, false, pg_sys::UUIDARRAYOID) };
        assert!(result.is_none());
    }
}
