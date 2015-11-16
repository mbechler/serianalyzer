/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 11.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;

import org.jboss.jandex.DotName;
import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class MethodReference implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -6109397570552531402L;

    private transient DotName typeName;
    private String method;
    private String signature;
    private boolean intf;
    private boolean stat;

    private BitSet parameterTaint = new BitSet();
    private BitSet parameterReturnTaint = new BitSet();
    private boolean calleeTaint;

    private transient List<Type> argumentTypes;
    private transient Type targetType;


    /**
     * 
     */
    MethodReference () {}


    /**
     * @param typeName
     * @param intf
     * @param method
     * @param stat
     * @param signature
     */
    public MethodReference ( DotName typeName, boolean intf, String method, boolean stat, String signature ) {
        super();
        this.typeName = typeName;
        this.intf = intf;
        this.method = method;
        this.stat = stat;
        this.signature = signature;
    }


    private void writeObject ( ObjectOutputStream oos ) throws IOException {
        oos.defaultWriteObject();
        oos.writeUTF(this.typeName.toString());

        oos.writeBoolean(this.targetType != null);
        if ( this.targetType != null ) {
            oos.writeUTF(this.targetType.toString());
        }

        if ( this.argumentTypes != null ) {
            oos.writeBoolean(true);
            oos.writeInt(this.argumentTypes != null ? this.argumentTypes.size() : 0);
            for ( Type t : this.argumentTypes ) {
                oos.writeUTF(t != null ? t.toString() : null);
            }
        }
        else {
            oos.writeBoolean(false);
        }
    }


    private void readObject ( ObjectInputStream ois ) throws ClassNotFoundException, IOException {
        ois.defaultReadObject();

        String tname = ois.readUTF();
        if ( tname != null ) {
            this.typeName = DotName.createSimple(tname);
        }

        if ( ois.readBoolean() ) {
            this.targetType = Type.getType(ois.readUTF());
        }

        boolean haveArgs = ois.readBoolean();
        if ( haveArgs ) {
            int argc = ois.readInt();
            List<Type> argTypes = new ArrayList<>();
            for ( int i = 0; i < argc; i++ ) {
                tname = ois.readUTF();
                argTypes.add(Type.getType(tname));
            }
            this.argumentTypes = argTypes;
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        StringBuilder taintStatus = new StringBuilder();
        int params = Type.getArgumentTypes(this.signature).length;
        for ( int i = 0; i < params; i++ ) {
            taintStatus.append(this.parameterTaint.get(i) ? 'T' : 'U');
        }
        char callerTaint = this.calleeTaint ? 'T' : 'U';

        StringBuilder argTypeString = new StringBuilder();
        if ( this.argumentTypes != null ) {
            argTypeString.append('/');
            argTypeString.append('(');
            for ( Type type : this.argumentTypes ) {
                argTypeString.append(type);
                argTypeString.append(',');
            }
            argTypeString.append(')');
        }
        return String.format("%s%s%s [%s]%s %s[%s]", //$NON-NLS-1$
            this.typeName,
            this.stat ? "::" : "->", this.method, this.signature, argTypeString, callerTaint, taintStatus); //$NON-NLS-1$ //$NON-NLS-2$

    }


    /**
     * @return the called target type
     */
    public Type getTargetType () {
        return this.targetType;
    }


    /**
     * @param targetType
     *            the targetType to set
     */
    public void setTargetType ( Type targetType ) {
        this.targetType = targetType;
    }


    /**
     * @return whether the target type is a interface
     */
    public boolean isInterface () {
        return this.intf;
    }


    /**
     * @return the stat
     */
    public boolean isStatic () {
        return this.stat;
    }


    /**
     * @return the typeName
     */
    public DotName getTypeName () {
        return this.typeName;
    }


    /**
     * @return the method
     */
    public String getMethod () {
        return this.method;
    }


    /**
     * @return the signature
     */
    public String getSignature () {
        return this.signature;
    }


    /**
     * @param i
     * @return whether the parameter is tainted
     */
    public boolean isParameterTainted ( int i ) {
        return this.parameterTaint.get(i);
    }


    /**
     * @param i
     * @return taint status changed
     */
    public boolean taintParameter ( int i ) {
        boolean old = isParameterTainted(i);
        this.parameterTaint.set(i);
        return !old;
    }


    /**
     * 
     * @param i
     * @return wheteher all return values from the argument should be tainted
     */
    public boolean isTaintParameterReturn ( int i ) {
        return this.parameterReturnTaint.get(i);
    }


    /**
     * 
     * @param i
     * @return taint status changed
     */
    public boolean taintParameterReturns ( int i ) {
        boolean old = isTaintParameterReturn(i);
        this.parameterReturnTaint.set(i);
        return !old;
    }


    /**
     * @return whether the callee is tainted
     */
    public boolean isCalleeTainted () {
        return this.calleeTaint;
    }


    /**
     * 
     * @return whether taint status changed
     */
    public boolean taintCallee () {
        boolean old = this.calleeTaint;
        this.calleeTaint = true;
        return !old;
    }


    /**
     * @return the argumentTypes
     */
    public List<Type> getArgumentTypes () {
        return this.argumentTypes;
    }


    /**
     * @param argumentTypes
     *            the argumentTypes to set
     */
    public void setArgumentTypes ( List<Type> argumentTypes ) {
        this.argumentTypes = argumentTypes;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode () {
        final int prime = 31;
        int result = 1;
        result = prime * result + ( ( this.argumentTypes == null ) ? 0 : this.argumentTypes.hashCode() );
        result = prime * result + ( this.calleeTaint ? 1231 : 1237 );
        result = prime * result + ( this.intf ? 1231 : 1237 );
        result = prime * result + ( ( this.method == null ) ? 0 : this.method.hashCode() );
        result = prime * result + ( ( this.parameterReturnTaint == null ) ? 0 : this.parameterReturnTaint.hashCode() );
        result = prime * result + ( ( this.parameterTaint == null ) ? 0 : this.parameterTaint.hashCode() );
        result = prime * result + ( ( this.signature == null ) ? 0 : this.signature.hashCode() );
        result = prime * result + ( this.stat ? 1231 : 1237 );
        result = prime * result + ( ( this.typeName == null ) ? 0 : this.typeName.hashCode() );
        return result;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals ( Object obj ) {
        if ( this == obj )
            return true;
        if ( obj == null )
            return false;
        if ( getClass() != obj.getClass() )
            return false;
        MethodReference other = (MethodReference) obj;
        if ( this.argumentTypes == null ) {
            if ( other.argumentTypes != null )
                return false;
        }
        else if ( !this.argumentTypes.equals(other.argumentTypes) )
            return false;
        if ( this.calleeTaint != other.calleeTaint )
            return false;
        if ( this.intf != other.intf )
            return false;
        if ( this.method == null ) {
            if ( other.method != null )
                return false;
        }
        else if ( !this.method.equals(other.method) )
            return false;
        if ( this.parameterReturnTaint == null ) {
            if ( other.parameterReturnTaint != null )
                return false;
        }
        else if ( !this.parameterReturnTaint.equals(other.parameterReturnTaint) )
            return false;
        if ( this.parameterTaint == null ) {
            if ( other.parameterTaint != null )
                return false;
        }
        else if ( !this.parameterTaint.equals(other.parameterTaint) )
            return false;
        if ( this.signature == null ) {
            if ( other.signature != null )
                return false;
        }
        else if ( !this.signature.equals(other.signature) )
            return false;
        if ( this.stat != other.stat )
            return false;
        if ( this.typeName == null ) {
            if ( other.typeName != null )
                return false;
        }
        else if ( !this.typeName.toString().equals(other.typeName.toString()) )
            return false;
        return true;
    }


    /**
     * @param name
     * @return a new method reference for the given target type
     */
    public MethodReference adaptToType ( DotName name ) {
        MethodReference ref = new MethodReference(name, false, this.getMethod(), this.stat, this.getSignature());
        ref.calleeTaint = this.calleeTaint;
        ref.parameterTaint = (BitSet) this.parameterTaint.clone();
        ref.parameterReturnTaint = (BitSet) this.parameterReturnTaint.clone();
        if ( this.argumentTypes != null ) {
            ref.argumentTypes = new ArrayList<>(this.argumentTypes);
        }
        return ref;
    }


    /**
     * @return a new method that reflects full taint status
     */
    public MethodReference fullTaint () {
        MethodReference ref = new MethodReference(this.getTypeName(), this.isInterface(), this.getMethod(), this.isStatic(), this.getSignature());
        ref.calleeTaint = true;
        Type[] t = Type.getArgumentTypes(this.getSignature());
        for ( int i = 0; i < t.length; i++ ) {
            ref.taintParameter(i);
        }
        return ref;
    }


    /**
     * @param other
     * @return a new method that reflects the union of the two methods taint states
     */
    public MethodReference maxTaint ( MethodReference other ) {
        if ( !this.comparable().equals(other.comparable()) ) {
            throw new IllegalArgumentException("Not same method"); //$NON-NLS-1$
        }
        MethodReference ref = new MethodReference(this.getTypeName(), this.isInterface(), this.getMethod(), this.isStatic(), this.getSignature());
        ref.calleeTaint = this.calleeTaint || other.calleeTaint;
        Type[] t = Type.getArgumentTypes(this.getSignature());
        for ( int i = 0; i < t.length; i++ ) {
            if ( this.isParameterTainted(i) || other.isParameterTainted(i) ) {
                ref.taintParameter(i);
            }
            if ( this.isTaintParameterReturn(i) || other.isTaintParameterReturn(i) ) {
                ref.taintParameterReturns(i);
            }
        }
        return ref;
    }


    /**
     * @return a compareable type name without tainting information
     */
    public MethodReference comparable () {
        return new MethodReference(this.getTypeName(), this.isInterface(), this.getMethod(), this.isStatic(), this.getSignature());
    }

}
