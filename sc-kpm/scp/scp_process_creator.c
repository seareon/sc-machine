/*
-----------------------------------------------------------------------------
This source file is part of OSTIS (Open Semantic Technology for Intelligent Systems)
For the latest info, see http://www.ostis.net

Copyright (c) 2010-2013 OSTIS

OSTIS is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

OSTIS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with OSTIS.  If not, see <http://www.gnu.org/licenses/>.
-----------------------------------------------------------------------------
*/

#include "sc_memory_headers.h"
#include "scp_process_creator.h"
#include "scp_interpreter_utils.h"
#include "scp_keynodes.h"
#include "scp_utils.h"

#include <stdio.h>
#include <glib.h>

sc_event *event_program_iterpretation;

scp_result copy_parameter_set(sc_memory_context *context, scp_operand *set, scp_operand *call_params, GHashTable *table)
{
    scp_operand arc1, arc2, elem, new_elem, ordinal;
    scp_iterator3 *it;
    MAKE_DEFAULT_ARC_ASSIGN(arc1);
    MAKE_DEFAULT_ARC_ASSIGN(arc2);
    MAKE_DEFAULT_OPERAND_ASSIGN(elem);
    MAKE_DEFAULT_OPERAND_ASSIGN(new_elem);
    it = scp_iterator3_new(context, set, &arc1, &elem);
    while (SCP_RESULT_TRUE == scp_iterator3_next(context, it, set, &arc1, &elem))
    {
        arc1.param_type = SCP_FIXED;
        ordinal.param_type = SCP_ASSIGN;
        resolve_ordinal_rrel(context, &arc1, &ordinal);
        ordinal.param_type = SCP_FIXED;
        arc1.param_type = SCP_ASSIGN;
        new_elem.param_type = SCP_ASSIGN;
        if (SCP_RESULT_TRUE != searchElStr5(context, call_params, &arc1, &new_elem, &arc2, &ordinal))
        {
            scp_iterator3_free(it);
            return print_error("Illegal procedure parameter", "Call parameter missed");
        }
        new_elem.param_type = SCP_FIXED;
        g_hash_table_insert(table, MAKE_HASH(elem), MAKE_HASH(new_elem));
    }
    scp_iterator3_free(it);
    return SCP_RESULT_TRUE;
}

scp_result copy_const_set(sc_memory_context *context, scp_operand *set, GHashTable *table)
{
    scp_operand arc1, elem;
    scp_iterator3 *it;
    MAKE_DEFAULT_ARC_ASSIGN(arc1);
    MAKE_DEFAULT_OPERAND_ASSIGN(elem);
    it = scp_iterator3_new(context, set, &arc1, &elem);
    while (SCP_RESULT_TRUE == scp_iterator3_next(context, it, set, &arc1, &elem))
    {
        if (TRUE == g_hash_table_contains(table, MAKE_HASH(elem)))
        {
            continue;
        }
        g_hash_table_insert(table, MAKE_HASH(elem), MAKE_HASH(elem));
    }
    scp_iterator3_free(it);
    return SCP_RESULT_TRUE;
}

scp_result copy_var_set(sc_memory_context *context, scp_operand *set, GHashTable *table)
{
    scp_operand arc, arc1, arc2, elem, new_elem;
    scp_iterator3 *it;
    MAKE_DEFAULT_ARC_ASSIGN(arc);
    MAKE_DEFAULT_ARC_ASSIGN(arc1);
    MAKE_DEFAULT_ARC_ASSIGN(arc2);
    MAKE_DEFAULT_OPERAND_ASSIGN(elem);
    MAKE_DEFAULT_NODE_ASSIGN(new_elem);
    new_elem.element_type = new_elem.element_type | scp_type_var;
    it = scp_iterator3_new(context, set, &arc1, &elem);
    while (SCP_RESULT_TRUE == scp_iterator3_next(context, it, set, &arc1, &elem))
    {
        if (TRUE == g_hash_table_contains(table, MAKE_HASH(elem)))
        {
            continue;
        }
        genEl(context, &new_elem);
        g_hash_table_insert(table, MAKE_HASH(elem), MAKE_HASH(new_elem));
    }
    scp_iterator3_free(it);
    return SCP_RESULT_TRUE;
}

scp_result copy_copying_const_set(sc_memory_context *context, scp_operand *set, GHashTable *table)
{
    scp_operand arc1, elem, new_elem;
    scp_iterator3 *it;
    MAKE_DEFAULT_ARC_ASSIGN(arc1);
    MAKE_DEFAULT_OPERAND_ASSIGN(elem);
    MAKE_DEFAULT_NODE_ASSIGN(new_elem);
    new_elem.element_type = new_elem.element_type | scp_type_const;
    it = scp_iterator3_new(context, set, &arc1, &elem);
    while (SCP_RESULT_TRUE == scp_iterator3_next(context, it, set, &arc1, &elem))
    {
        if (TRUE == g_hash_table_contains(table, MAKE_HASH(elem)))
        {
            continue;
        }
        genEl(context, &new_elem);
        g_hash_table_insert(table, MAKE_HASH(elem), MAKE_HASH(new_elem));
    }
    scp_iterator3_free(it);
    return SCP_RESULT_TRUE;
}

gboolean compare_keys(gpointer key, gpointer value, gpointer user_data)
{
    if (key == user_data)
        return TRUE;
    else
        return FALSE;
}

sc_addr gen_copy_element(sc_memory_context *context, sc_addr elem, GHashTable *copies_hash)
{
    scp_operand op_test;
    gpointer result;
    result = g_hash_table_find(copies_hash, compare_keys, MAKE_SC_ADDR_HASH(elem));
    if (result != NULL)
    {
        return resolve_sc_addr_from_pointer(result);
    }
    if (SCP_RESULT_TRUE == check_type(context, elem, scp_type_node))
    {
        printf("Gen node\n");
        sc_addr node;
        sc_type type;
        sc_memory_get_element_type(context, elem, &type);
        node = sc_memory_node_new(context, type);
        op_test.addr = node;
        printEl(context, &op_test);
        g_hash_table_insert(copies_hash, MAKE_SC_ADDR_HASH(elem), MAKE_SC_ADDR_HASH(node));
        return node;
    }
    else
    {
        printf("Gen arc\n");
        sc_addr begin, end, new_begin, new_end, new_arc;
        sc_type type;
        sc_memory_get_arc_begin(context, elem, &begin);
        sc_memory_get_arc_end(context, elem, &end);
        new_begin = gen_copy_element(context, begin, copies_hash);
        new_end = gen_copy_element(context, end, copies_hash);
        sc_memory_get_element_type(context, elem, &type);
        new_arc = sc_memory_arc_new(context, type, new_begin, new_end);
        op_test.addr = new_arc;
        printEl(context, &op_test);
        g_hash_table_insert(copies_hash, MAKE_SC_ADDR_HASH(elem), MAKE_SC_ADDR_HASH(new_arc));
        return new_arc;
    }
}

void gen_copy_modifier_arc(sc_memory_context *context,sc_addr arc, sc_addr begin, GHashTable *copies_hash) {
    scp_operand op_test;
    sc_addr end, new_end, new_arc;
    sc_type type;
    c_memory_get_arc_end(context, arc, &end);
    new_end = gen_copy_element(context, end, copies_hash);
    sc_memory_get_element_type(context, arc, &type);
    new_arc = sc_memory_arc_new(context, type, begin, new_end);
    op_test.addr = new_arc;
    printEl(context, &op_test);
    g_hash_table_insert(copies_hash, MAKE_SC_ADDR_HASH(arc), MAKE_SC_ADDR_HASH(new_arc));
}

scp_result gen_copy(sc_memory_context *context, scp_operand *operator_set, scp_operand *parameter_set, GHashTable *copies_hash) {
    scp_operand arc1, arc2, operator_arc, curr_operator, operator_type, operator_input, operand_arc, curr_operand, modifier, modifier_arc, operand_arc_pattern;
    scp_iterator3 *it, *it1, *it2;
    scp_bool order_rel;

    MAKE_DEFAULT_ARC_ASSIGN(operator_arc);
    MAKE_DEFAULT_ARC_ASSIGN(operand_arc);
    MAKE_DEFAULT_ARC_ASSIGN(arc1);
    MAKE_DEFAULT_ARC_ASSIGN(arc2);
    MAKE_DEFAULT_ARC_ASSIGN(modifier_arc);
    modifier_arc.erase = SCP_TRUE;
    MAKE_DEFAULT_OPERAND_ASSIGN(curr_operator);
    MAKE_DEFAULT_OPERAND_ASSIGN(operator_type);
    MAKE_DEFAULT_OPERAND_ASSIGN(operator_input);
    MAKE_DEFAULT_OPERAND_ASSIGN(curr_operand);
    MAKE_DEFAULT_OPERAND_ASSIGN(modifier);
    MAKE_DEFAULT_OPERAND_ASSIGN(operand_arc_pattern);
    operand_arc_pattern.element_type = scp_type_arc_common | scp_type_const;


    it = scp_iterator3_new(context, operator_set, &operator_arc, &curr_operator);
    while(SCP_RESULT_TRUE == scp_iterator3_next(context, it, operator_set, &operator_arc, &curr_operator)) {
        curr_operator.param_type = SCP_FIXED;
        operator_arc.param_type = SCP_FIXED;

        gen_copy_element(context, curr_operator.addr, copies_hash);
        gen_copy_element(context, operator_arc.addr, copies_hash);

        if (SCP_RESULT_TRUE == searchElStr3(context, &rrel_init, &arc1, &operator_arc)) {
            gen_copy_modifier_arc(context, arc1.addr, rrel_init.addr, copies_hash);
        }

        operator_type.param_type = SCP_ASSIGN;
        operator_input.param_type = SCP_ASSIGN;
        it1 = scp_iterator3_new(context, &operator_input, &arc1, &curr_operator);
        while (SCP_RESULT_TRUE == scp_iterator3_next(context, it1, &operator_input, &arc1, &curr_operator))
        {
            operator_input.param_type = SCP_FIXED;

            if (SCP_RESULT_TRUE == searchElStr3(context, &scp_operator_atomic_type, &arc2, &operator_input))
            {
                gen_copy_element(context, arc1.addr, copies_hash);
                operator_type.addr = operator_input.addr;
                operator_input.param_type = SCP_ASSIGN;
                continue;
            }

            operator_input.param_type = SCP_ASSIGN;
        }
        scp_iterator3_free(it1);
        operator_type.param_type = SCP_FIXED;

        // Operands loop
        it1 = scp_iterator3_new(context, &curr_operator, &operand_arc, &curr_operand);
        while (SCP_RESULT_TRUE == scp_iterator3_next(context, it1, &curr_operator, &operand_arc, &curr_operand))
        {
            curr_operand.param_type = SCP_FIXED;
            operand_arc.param_type = SCP_FIXED;

            order_rel = SCP_FALSE;

            operand_arc_pattern.addr = operand_arc.addr;
            if (SCP_TRUE == ifType(context, &operand_arc_pattern))
            {
                if (SCP_TRUE != searchElStr3(context, operator_set, &arc1, &curr_operand))
                {
                    operand_arc.param_type = SCP_ASSIGN;
                    curr_operand.param_type = SCP_ASSIGN;
                    continue;
                }
                else
                {
                    order_rel = SCP_TRUE;
                }
            }

            gen_copy_element(context, curr_operand.addr, copies_hash);
            gen_copy_element(context, operand_arc.addr, copies_hash);


            // Operand modifiers loop
            it2 = scp_iterator3_new(context, &modifier, &modifier_arc, &operand_arc);
            while (SCP_RESULT_TRUE == scp_iterator3_next(context, it2, &modifier, &modifier_arc, &operand_arc))
            {
                modifier.param_type = SCP_FIXED;
                modifier_arc.param_type = SCP_FIXED;
                if (SCP_TRUE == order_rel)
                {
                    if (SCP_TRUE == ifCoin(context, &nrel_goto, &modifier)
                        || SCP_TRUE == ifCoin(context, &nrel_else, &modifier)
                        || SCP_TRUE == ifCoin(context, &nrel_then, &modifier)
                        || SCP_TRUE == ifCoin(context, &nrel_error, &modifier))
                    {
                        gen_copy_modifier_arc(context, arc1.addr, modifier_arc.addr, copies_hash);
                        modifier_arc.param_type = SCP_ASSIGN;
                        modifier.param_type = SCP_ASSIGN;
                        break;
                    }
                    else
                    {
                        modifier_arc.param_type = SCP_ASSIGN;
                        modifier.param_type = SCP_ASSIGN;
                        continue;
                    }
                }
                if (SCP_RESULT_TRUE == ifCoin(context, &rrel_scp_var, &modifier) && SCP_RESULT_TRUE != searchElStr5(context, parameter_set, &arc1, &curr_operand, &arc2, &rrel_in)) {       //!!!!!!!!!!
                    gen_copy_modifier_arc(context, arc1.addr, modifier_arc.addr, copies_hash);
                }
                else {
                    gen_copy_modifier_arc(context, arc1.addr, modifier_arc.addr, copies_hash);
                }

                modifier_arc.param_type = SCP_ASSIGN;
                modifier.param_type = SCP_ASSIGN;
                printf("Output from modifier\n");
            }
            scp_iterator3_free(it2);

            operand_arc.param_type = SCP_ASSIGN;
            curr_operand.param_type = SCP_ASSIGN;
            printf("Output from curr_operand\n");
       }
       scp_iterator3_free(it1);

       operator_arc.param_type = SCP_ASSIGN;
       curr_operator.param_type = SCP_ASSIGN;
       printf("Output from curr_operator\n");
    }
    scp_iterator3_free(it);
    return SCP_TRUE;
}

sc_result create_scp_process(const sc_event *event, sc_addr arg)
{
    scp_operand arc1, arc2, arc3, scp_procedure_node, vars_set, consts_set, params_set,
                scp_process_node, node1, question_node, call_parameters, init_operator, scp_procedure_operators;
    GHashTable *copies_hash;
    scp_iterator5 *it;
    sc_char init_flag = SC_TRUE;
    copies_hash = g_hash_table_new(NULL, NULL);

    MAKE_DEFAULT_OPERAND_FIXED(arc1);
    MAKE_DEFAULT_ARC_ASSIGN(arc2);
    MAKE_DEFAULT_OPERAND_ASSIGN(scp_procedure_node);
    MAKE_DEFAULT_OPERAND_ASSIGN(scp_procedure_operators);
    MAKE_DEFAULT_OPERAND_FIXED(scp_process_node);
    arc1.addr = arg;
    arc1.element_type = scp_type_arc_pos_const_perm;

    MAKE_DEFAULT_NODE_ASSIGN(node1);
    MAKE_DEFAULT_NODE_ASSIGN(question_node);
    MAKE_DEFAULT_NODE_ASSIGN(call_parameters);
    if (SCP_RESULT_TRUE != ifVarAssign(s_default_ctx, &arc1))
    {
        return SC_RESULT_ERROR;
    }
    if (SCP_RESULT_TRUE != ifType(s_default_ctx, &arc1))
    {
        return SC_RESULT_OK;
    }

    if (SCP_RESULT_TRUE != searchElStr3(s_default_ctx, &node1, &arc1, &question_node))
    {
        //print_error("scp-process creating", "Can't find interpreting request node");
        return SC_RESULT_ERROR;
    }

    question_node.param_type = SCP_FIXED;
    if (SCP_RESULT_TRUE != searchElStr3(s_default_ctx, &question_scp_interpretation_request, &arc2, &question_node))
    {
        return SC_RESULT_ERROR;
    }
    arc1.erase = SCP_TRUE;
    eraseEl(s_default_ctx, &arc1);
    MAKE_DEFAULT_ARC_ASSIGN(arc1);

    if (SCP_RESULT_TRUE != searchElStr5(s_default_ctx, &question_node, &arc1, &scp_procedure_node, &arc2, &(ordinal_rrels[1])))
    {
        print_error("scp-process creating", "Can't find scp-procedure");
        return SC_RESULT_ERROR;
    }
    scp_procedure_node.param_type = SCP_FIXED;
    if (SCP_RESULT_TRUE != searchElStr5(s_default_ctx, &question_node, &arc1, &call_parameters, &arc2, &(ordinal_rrels[2])))
    {
        print_error("scp-process creating", "Can't find call parameters");
        return SC_RESULT_ERROR;
    }
    call_parameters.param_type = SCP_FIXED;

    //scp-procedure search
    if (SCP_RESULT_TRUE != searchElStr3(s_default_ctx, &scp_program, &arc1, &scp_procedure_node))
    {
        return SC_RESULT_ERROR;
    }
    scp_procedure_node.param_type = SCP_FIXED;
    MAKE_DEFAULT_ARC_ASSIGN(arc1);
    MAKE_DEFAULT_ARC_ASSIGN(arc2);
    MAKE_COMMON_ARC_ASSIGN(arc3);

    MAKE_DEFAULT_OPERAND_ASSIGN(vars_set);
    if(SCP_RESULT_TRUE == searchElStr5(s_default_ctx, &scp_procedure_node, &arc3, &vars_set, &arc2, &nrel_scp_program_var)) {
        vars_set.param_type = SCP_FIXED;
    }
    else {
        return SC_RESULT_ERROR;
    }
    MAKE_DEFAULT_OPERAND_ASSIGN(consts_set);
    if(SCP_RESULT_TRUE == searchElStr5(s_default_ctx, &scp_procedure_node, &arc3, &consts_set, &arc2, &nrel_scp_program_const)) {
        consts_set.param_type = SCP_FIXED;
    }
    else {
        return SC_RESULT_ERROR;
    }
    MAKE_DEFAULT_OPERAND_ASSIGN(params_set);
    if(SCP_RESULT_TRUE == searchElStr5(s_default_ctx, &scp_procedure_node, &arc2, &params_set, &arc2, &rrel_params)) {
        params_set.param_type = SCP_FIXED;
    }
    if(SCP_RESULT_TRUE ==  searchElStr5(s_default_ctx, &scp_procedure_node, &arc1, &scp_procedure_operators, &arc2, &rrel_operators)) {
        scp_procedure_operators.param_type = SCP_FIXED;
    }
    else {
        return SC_RESULT_ERROR;
    }

    if (SCP_RESULT_TRUE != copy_parameter_set(s_default_ctx, &params_set, &call_parameters, copies_hash))
    {
        return SC_RESULT_OK;
    }
    if (SCP_RESULT_TRUE != copy_var_set(s_default_ctx, &vars_set, copies_hash))
    {
        return SC_RESULT_OK;
    }
    if (SCP_RESULT_TRUE != copy_copying_const_set(s_default_ctx, &vars_set, copies_hash))
    {
        return SC_RESULT_OK;
    }
    if (SCP_RESULT_TRUE != copy_const_set(s_default_ctx, &consts_set, copies_hash))
    {
        return SC_RESULT_OK;
    }

    MAKE_COMMON_ARC_ASSIGN(arc1);
    MAKE_DEFAULT_ARC_ASSIGN(arc2);
    MAKE_DEFAULT_NODE_ASSIGN(scp_process_node);
    if(SCP_RESULT_TRUE == genElStr5(s_default_ctx, &question_node, &arc1, &scp_process_node, &arc2, &nrel_scp_process)) {
        scp_process_node.param_type = SCP_FIXED;
    }

    MAKE_DEFAULT_ARC_ASSIGN(arc1);
    genElStr3(s_default_ctx, &scp_process, &arc1, &scp_process_node);
    printEl(s_default_ctx, &scp_process_node);

    g_hash_table_insert(copies_hash, MAKE_HASH(scp_procedure_operators), MAKE_HASH(scp_process_node));

   if(SCP_RESULT_TRUE != gen_copy(s_default_ctx, &scp_procedure_operators, &params_set, copies_hash)) {
       return SC_RESULT_ERROR;
   }

    g_hash_table_destroy(copies_hash);

    MAKE_DEFAULT_OPERAND_ASSIGN(init_operator);
    it = scp_iterator5_new(s_default_ctx, &scp_process_node, &arc1, &init_operator, &arc2, &rrel_init);
    while (SCP_RESULT_TRUE == scp_iterator5_next(s_default_ctx, it, &scp_process_node, &arc1, &init_operator, &arc2, &rrel_init))       // не заходит??
    {
        init_flag = SC_FALSE;
        init_operator.param_type = SCP_FIXED;
        set_active_operator(s_default_ctx, &init_operator);
        init_operator.param_type = SCP_ASSIGN;
    }
    scp_iterator5_free(it);

    if (SC_TRUE == init_flag)
    {
        print_error("scp-process interpreting", "Can't find init operator");
        mark_scp_process_as_useless(s_default_ctx, &scp_process_node);
    }

    return SC_RESULT_OK;
}

scp_result scp_process_creator_init()
{
    event_program_iterpretation = sc_event_new(s_default_ctx, question_initiated.addr, SC_EVENT_ADD_OUTPUT_ARC, 0, create_scp_process, 0);
    if (event_program_iterpretation == null_ptr)
        return SCP_RESULT_ERROR;
    return SCP_RESULT_TRUE;
}

scp_result scp_process_creator_shutdown()
{
    sc_event_destroy(event_program_iterpretation);
    return SCP_RESULT_TRUE;
}
