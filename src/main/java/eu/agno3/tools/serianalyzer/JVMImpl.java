/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 15.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.jboss.jandex.DotName;
import org.objectweb.asm.Label;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import eu.agno3.tools.serianalyzer.types.BaseType;
import eu.agno3.tools.serianalyzer.types.BasicConstant;
import eu.agno3.tools.serianalyzer.types.BasicVariable;
import eu.agno3.tools.serianalyzer.types.FieldReference;
import eu.agno3.tools.serianalyzer.types.MultiAlternatives;
import eu.agno3.tools.serianalyzer.types.ObjectReferenceConstant;
import eu.agno3.tools.serianalyzer.types.SimpleType;


/**
 * @author mbechler
 *
 */
public final class JVMImpl {

    private static final Logger log = Logger.getLogger(JVMImpl.class);


    /**
     * @param opcode
     * @param label
     * @param s
     * @return
     */
    static boolean handleJVMJump ( int opcode, Label label, JVMStackState s ) {
        boolean tainted;
        switch ( opcode ) {
        case Opcodes.IF_ICMPEQ:
        case Opcodes.IF_ICMPNE:
        case Opcodes.IF_ICMPLT:
        case Opcodes.IF_ICMPGE:
        case Opcodes.IF_ICMPGT:
        case Opcodes.IF_ICMPLE:
        case Opcodes.IF_ACMPEQ:
        case Opcodes.IF_ACMPNE:
            BaseType o1 = s.pop();
            BaseType o2 = s.pop();
            tainted = ! ( o1 != null ) || ! ( o2 != null ) || o1.isTainted() || o2.isTainted();
            break;
        case Opcodes.IFEQ:
        case Opcodes.IFNE:
        case Opcodes.IFLT:
        case Opcodes.IFGE:
        case Opcodes.IFGT:
        case Opcodes.IFLE:
        case Opcodes.IFNULL:
        case Opcodes.IFNONNULL:
            BaseType c = s.pop();
            tainted = ( c == null || c.isTainted() );
            break;

        case Opcodes.JSR:
            s.push(new BasicConstant(Type.INT_TYPE, label));
            tainted = false;
            break;
        case Opcodes.GOTO:
            tainted = false;
            break;
        default:
            log.warn("Unsupported opcode " + opcode); //$NON-NLS-1$
            tainted = true;
        }
        return tainted;
    }


    /**
     * @param opcode
     * @param operand
     * @param s
     */
    static void handleJVMIntInsn ( int opcode, int operand, JVMStackState s ) {
        switch ( opcode ) {
        case Opcodes.BIPUSH:
            s.push(new BasicConstant(Type.BYTE_TYPE, operand));
            break;
        case Opcodes.SIPUSH:
            s.push(new BasicConstant(Type.SHORT_TYPE, operand));
            break;
        case Opcodes.NEWARRAY:
            s.pop();
            s.push(new BasicVariable(makeBasicArrayType(operand), "array", false)); //$NON-NLS-1$
        }
    }


    /**
     * @param opcode
     * @param s
     */
    static void handleJVMInsn ( int opcode, JVMStackState s ) {
        BaseType o1;
        BaseType o2;
        BaseType o3;
        List<BaseType> l1;
        List<BaseType> l2;
        switch ( opcode ) {
        case Opcodes.NOP:
            break;

        case Opcodes.ARRAYLENGTH:
            o1 = s.pop();
            s.push(new BasicConstant(Type.INT_TYPE, 0, ! ( o1 != null && !o1.isTainted() )));
            break;
        case Opcodes.ACONST_NULL:
            s.push(new BasicConstant(Type.VOID_TYPE, "<null>")); //$NON-NLS-1$
            break;
        case Opcodes.ICONST_M1:
        case Opcodes.ICONST_0:
        case Opcodes.ICONST_1:
        case Opcodes.ICONST_2:
        case Opcodes.ICONST_3:
        case Opcodes.ICONST_4:
        case Opcodes.ICONST_5:
            s.push(new BasicConstant(Type.INT_TYPE, opcode - 3));
            break;
        case Opcodes.LCONST_0:
        case Opcodes.LCONST_1:
            s.push(new BasicConstant(Type.LONG_TYPE, opcode - 9L));
            break;
        case Opcodes.FCONST_0:
        case Opcodes.FCONST_1:
        case Opcodes.FCONST_2:
            s.push(new BasicConstant(Type.FLOAT_TYPE, opcode - 11f));
            break;
        case Opcodes.DCONST_0:
        case Opcodes.DCONST_1:
            s.push(new BasicConstant(Type.DOUBLE_TYPE, opcode - 14d));
            break;
        case Opcodes.IALOAD:
        case Opcodes.LALOAD:
        case Opcodes.FALOAD:
        case Opcodes.DALOAD:
        case Opcodes.BALOAD:
        case Opcodes.CALOAD:
        case Opcodes.SALOAD:
            o1 = s.pop();
            o2 = s.pop();
            s.push(new BasicVariable(toType(opcode), "primitive array elem", ( o1 == null || o1.isTainted() ) | ( o2 == null || o2.isTainted() ))); //$NON-NLS-1$
            break;

        case Opcodes.AALOAD:
            o1 = s.pop();
            o2 = s.pop();
            if ( o1 != null && o2 instanceof SimpleType && ( (SimpleType) o2 ).getType().toString().startsWith("[") ) { //$NON-NLS-1$
                Type atype = Type.getType( ( (SimpleType) o2 ).getType().toString().substring(1));
                if ( o2.getAlternativeTypes() != null && !o2.getAlternativeTypes().isEmpty() ) {
                    s.clear();
                    break;
                }
                s.push(new BasicVariable(atype, "array elem " + atype, o1.isTainted() | o2.isTainted())); //$NON-NLS-1$
            }
            else {
                s.clear();
            }
            break;

        case Opcodes.IASTORE:
        case Opcodes.LASTORE:
        case Opcodes.FASTORE:
        case Opcodes.DASTORE:
        case Opcodes.AASTORE:
        case Opcodes.BASTORE:
        case Opcodes.CASTORE:
        case Opcodes.SASTORE:
            s.pop(3);
            break;

        case Opcodes.POP2:
            s.pop();
        case Opcodes.MONITORENTER:
        case Opcodes.MONITOREXIT:
        case Opcodes.POP:
            s.pop();
            break;

        case Opcodes.DUP:
            if ( !s.isEmpty() ) {
                o1 = s.pop();
                s.push(o1);
                s.push(o1);
            }
            break;
        case Opcodes.DUP_X1:
            o1 = s.pop();
            o2 = s.pop();
            s.push(o1);
            s.push(o2);
            s.push(o1);
            break;
        case Opcodes.DUP_X2:
            o1 = s.pop();
            o2 = s.pop();
            o3 = s.pop();
            s.push(o1);
            s.push(o3);
            s.push(o2);
            s.push(o1);
            break;
        case Opcodes.DUP2:
            l1 = s.popWord();
            if ( l1.isEmpty() ) {
                log.trace("DUP2 with unknown operand"); //$NON-NLS-1$
                s.clear();
            }
            else {
                s.pushWord(l1);
                s.pushWord(l1);
            }
            break;
        case Opcodes.DUP2_X1:
            l1 = s.popWord();
            o1 = s.pop();
            if ( l1.isEmpty() ) {
                log.trace("DUP2 with unknown operand"); //$NON-NLS-1$
                s.clear();
            }
            else {
                s.pushWord(l1);
                s.push(o1);
                s.pushWord(l1);
            }
            break;
        case Opcodes.DUP2_X2:
            l1 = s.popWord();
            l2 = s.popWord();
            if ( l1.isEmpty() || l2.isEmpty() ) {
                log.trace("DUP2 with unknown operand"); //$NON-NLS-1$
                s.clear();
            }
            else {
                s.pushWord(l1);
                s.pushWord(l2);
                s.pushWord(l1);
            }
            break;

        case Opcodes.SWAP:
            o1 = s.pop();
            o2 = s.pop();
            s.push(o1);
            s.push(o2);
            break;

        case Opcodes.IADD:
        case Opcodes.LADD:
        case Opcodes.FADD:
        case Opcodes.DADD:
        case Opcodes.ISUB:
        case Opcodes.LSUB:
        case Opcodes.FSUB:
        case Opcodes.DSUB:
        case Opcodes.IMUL:
        case Opcodes.LMUL:
        case Opcodes.FMUL:
        case Opcodes.DMUL:
        case Opcodes.IDIV:
        case Opcodes.LDIV:
        case Opcodes.FDIV:
        case Opcodes.DDIV:
        case Opcodes.IREM:
        case Opcodes.LREM:
        case Opcodes.FREM:
        case Opcodes.DREM:
        case Opcodes.IAND:
        case Opcodes.LAND:
        case Opcodes.IOR:
        case Opcodes.LOR:
        case Opcodes.IXOR:
        case Opcodes.LXOR:
        case Opcodes.LCMP:
        case Opcodes.FCMPL:
        case Opcodes.FCMPG:
        case Opcodes.DCMPL:
        case Opcodes.DCMPG:
            s.merge(2);
            break;

        case Opcodes.ISHL:
        case Opcodes.LSHL:
        case Opcodes.ISHR:
        case Opcodes.LSHR:
        case Opcodes.IUSHR:
        case Opcodes.LUSHR:
            s.pop(); // amount
            // ignore value
            break;

        case Opcodes.INEG:
        case Opcodes.F2I:
        case Opcodes.D2I:
        case Opcodes.L2I:
            s.push(cast(s.pop(), Type.INT_TYPE));
            break;

        case Opcodes.LNEG:
        case Opcodes.I2L:
        case Opcodes.F2L:
        case Opcodes.D2L:
            s.push(cast(s.pop(), Type.LONG_TYPE));
            break;

        case Opcodes.FNEG:
        case Opcodes.I2F:
        case Opcodes.L2F:
        case Opcodes.D2F:
            s.push(cast(s.pop(), Type.FLOAT_TYPE));

        case Opcodes.DNEG:
        case Opcodes.I2D:
        case Opcodes.L2D:
        case Opcodes.F2D:
            s.push(cast(s.pop(), Type.DOUBLE_TYPE));

        case Opcodes.I2B:
            s.push(cast(s.pop(), Type.BYTE_TYPE));
            break;
        case Opcodes.I2C:
            s.push(cast(s.pop(), Type.CHAR_TYPE));
            break;
        case Opcodes.I2S:
            s.push(cast(s.pop(), Type.SHORT_TYPE));
            break;

        case Opcodes.ARETURN:
            s.clear();
            break;

        case Opcodes.IRETURN:
        case Opcodes.LRETURN:
        case Opcodes.FRETURN:
        case Opcodes.DRETURN:
        case Opcodes.RETURN:
            if ( log.isTraceEnabled() ) {
                log.trace("Found return " + s.pop()); //$NON-NLS-1$
            }
            s.clear();
            break;

        case Opcodes.ATHROW:
            Object thrw = s.pop();
            log.trace("Found throw " + thrw); //$NON-NLS-1$
            s.clear();
            break;

        default:
            log.warn("Unsupported instruction code " + opcode); //$NON-NLS-1$
        }
    }


    /**
     * @param opcode
     * @param type
     * @param s
     */
    static void handleJVMTypeInsn ( int opcode, String type, JVMStackState s ) {
        BaseType o;
        switch ( opcode ) {
        case Opcodes.NEW:
            s.push(new ObjectReferenceConstant(false, Type.getObjectType(type), type.replace('/', '.')));
            break;
        case Opcodes.ANEWARRAY:
            s.pop();
            if ( type.charAt(0) == '[' ) {
                s.push(new BasicVariable(Type.getObjectType("[" + type), "array", false)); //$NON-NLS-1$//$NON-NLS-2$
            }
            else {
                s.push(new BasicVariable(Type.getObjectType("[L" + type + ";"), "array", false)); //$NON-NLS-1$//$NON-NLS-2$ //$NON-NLS-3$
            }
            break;
        case Opcodes.CHECKCAST:
            if ( log.isDebugEnabled() ) {
                log.debug("Checkcast " + type); //$NON-NLS-1$
            }
            o = s.pop();
            if ( o != null ) {
                o.addAlternativeType(Type.getObjectType(type));
                s.push(o);
            }
            else {
                s.clear();
            }
            break;
        case Opcodes.INSTANCEOF:
            o = s.pop();
            if ( o != null ) {
                o.addAlternativeType(Type.getObjectType(type));
            }
            s.push(new BasicConstant(Type.BOOLEAN_TYPE, "typeof " + o + " = " + type, ! ( o != null ) || o.isTainted())); //$NON-NLS-1$ //$NON-NLS-2$
            break;
        }
    }


    /**
     * @param opcode
     * @param var
     * @param s
     */
    static void handleVarInsn ( int opcode, int var, JVMStackState s ) {
        Set<BaseType> v;
        switch ( opcode ) {
        case Opcodes.LLOAD:
        case Opcodes.ILOAD:
        case Opcodes.FLOAD:
        case Opcodes.DLOAD:
        case Opcodes.ALOAD:
            v = s.getVariable(var);
            if ( log.isTraceEnabled() ) {
                log.trace("LOAD " + opcode + "@" + var + ":" + v); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            }
            if ( v == null || v.isEmpty() ) {
                s.push(new BasicVariable(toType(opcode), "unknown " + var, true)); //$NON-NLS-1$
            }
            else if ( v.size() == 1 ) {
                s.push(v.iterator().next());
            }
            else {
                Set<BaseType> alts = new HashSet<>();
                for ( BaseType o : v ) {
                    if ( o instanceof MultiAlternatives && ! ( (MultiAlternatives) o ).getAlternatives().isEmpty() ) {
                        alts.addAll( ( (MultiAlternatives) o ).getAlternatives());
                    }
                    else {
                        alts.add(o);
                    }
                }
                s.push(new MultiAlternatives(alts));
            }
            break;
        case Opcodes.LSTORE:
        case Opcodes.ISTORE:
        case Opcodes.FSTORE:
        case Opcodes.DSTORE:
        case Opcodes.ASTORE:
            s.getVariable(var).add(s.pop());
            break;
        case Opcodes.RET:
            break;
        default:
            log.warn("Unimplemented opcode " + opcode); //$NON-NLS-1$
        }
    }


    /**
     * @param cst
     * @param s
     */
    static void handleLdcInsn ( Object cst, JVMStackState s ) {
        if ( cst instanceof Type ) {
            int sort = ( (Type) cst ).getSort();
            // TODO: not really sure about this, but the type seems expected
            if ( sort == Type.OBJECT ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Constant type sort object " + cst); //$NON-NLS-1$
                }
                s.push(new BasicVariable(Type.getType("Ljava/lang/Class;"), "type " + cst, false)); //$NON-NLS-1$ //$NON-NLS-2$
            }
            else if ( sort == Type.ARRAY ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Constant type sort array" + cst); //$NON-NLS-1$
                }
                s.push(new BasicVariable(Type.getType("Ljava/lang/Class;"), "type " + cst, false)); //$NON-NLS-1$ //$NON-NLS-2$
            }
            else {
                log.warn("Unhandled constant type sort " + sort); //$NON-NLS-1$
            }
        }
        else if ( cst instanceof String || cst instanceof Integer || cst instanceof Float || cst instanceof Long || cst instanceof Double ) {
            Type type = typeFromClass(cst);
            s.push(new BasicVariable(type, "const prim " + cst + " type " + type, false)); //$NON-NLS-1$ //$NON-NLS-2$
        }
        else {
            log.warn("Unhandled constant type " + cst.getClass()); //$NON-NLS-1$
        }
    }


    /**
     * @param opcode
     * @param owner
     * @param name
     * @param desc
     * @param s
     */
    static void handleFieldInsn ( int opcode, String owner, String name, String desc, JVMStackState s ) {
        switch ( opcode ) {
        case Opcodes.GETFIELD:
            Object tgt = s.pop();
            if ( log.isTraceEnabled() ) {
                log.trace("From " + tgt); //$NON-NLS-1$
            }
        case Opcodes.GETSTATIC:
            // this can be more specific
            if ( log.isTraceEnabled() ) {
                log.trace("Load field " + name + " (" + desc + ")"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            }
            s.push(new FieldReference(DotName.createSimple(owner.replace('/', '.')), name, Type.getType(desc), false));
            break;
        case Opcodes.PUTFIELD:
            s.pop();
            s.pop();
            break;
        case Opcodes.PUTSTATIC:
            s.pop();
            break;
        default:
            log.warn("Unsupported opcode " + opcode); //$NON-NLS-1$
        }
    }


    /**
     * @param cst
     * @return
     */
    private static Type typeFromClass ( Object cst ) {
        if ( cst instanceof Integer ) {
            return Type.INT_TYPE;
        }
        else if ( cst instanceof Float ) {
            return Type.FLOAT_TYPE;
        }
        else if ( cst instanceof Long ) {
            return Type.LONG_TYPE;
        }
        else if ( cst instanceof Double ) {
            return Type.DOUBLE_TYPE;
        }
        return Type.getType(cst.getClass());
    }


    /**
     * @param opcode
     * @return
     */
    private static Type toType ( int opcode ) {
        switch ( opcode ) {
        case Opcodes.LLOAD:
            return Type.LONG_TYPE;
        case Opcodes.ILOAD:
            return Type.INT_TYPE;
        case Opcodes.FLOAD:
            return Type.FLOAT_TYPE;
        case Opcodes.DLOAD:
            return Type.DOUBLE_TYPE;
        case Opcodes.ALOAD:
            return Type.getType("Ljava/lang/Object;"); //$NON-NLS-1$
        case Opcodes.IALOAD:
            return Type.INT_TYPE;
        case Opcodes.LALOAD:
            return Type.LONG_TYPE;
        case Opcodes.FALOAD:
            return Type.FLOAT_TYPE;
        case Opcodes.DALOAD:
            return Type.DOUBLE_TYPE;
        case Opcodes.BALOAD:
            return Type.BYTE_TYPE;
        case Opcodes.CALOAD:
            return Type.CHAR_TYPE;
        case Opcodes.SALOAD:
            return Type.SHORT_TYPE;
        }
        return Type.VOID_TYPE;
    }


    /**
     * @param pop
     * @param type
     * @return
     */
    private static BaseType cast ( BaseType pop, Type type ) {
        if ( pop instanceof BasicConstant ) {
            return new BasicConstant(type, ( (BasicConstant) pop ).getValue(), ( (BasicConstant) pop ).isTainted());
        }
        else if ( pop != null ) {
            return new BasicVariable(type, pop.toString(), pop.isTainted());
        }

        return new BasicVariable(type, null, true);
    }


    /**
     * @param operand
     * @return
     */
    private static Type makeBasicArrayType ( int operand ) {

        switch ( operand ) {
        case Opcodes.T_BOOLEAN:
            return Type.getType("[Z"); //$NON-NLS-1$
        case Opcodes.T_BYTE:
            return Type.getType("[B"); //$NON-NLS-1$
        case Opcodes.T_CHAR:
            return Type.getType("[C"); //$NON-NLS-1$
        case Opcodes.T_DOUBLE:
            return Type.getType("[D"); //$NON-NLS-1$
        case Opcodes.T_FLOAT:
            return Type.getType("[F"); //$NON-NLS-1$
        case Opcodes.T_INT:
            return Type.getType("[I"); //$NON-NLS-1$
        case Opcodes.T_LONG:
            return Type.getType("[J"); //$NON-NLS-1$
        case Opcodes.T_SHORT:
            return Type.getType("[S"); //$NON-NLS-1$

        default:
            log.error("Unknown array type " + operand); //$NON-NLS-1$
        }
        return null;
    }


    /**
     * @param desc
     * @param dims
     * @param s
     */
    static void handleMultiANewArrayInsn ( String desc, int dims, JVMStackState s ) {
        s.pop(dims);
        s.push(new BasicVariable(Type.getType(desc), dims + "-dim array", false)); //$NON-NLS-1$
    }
}
