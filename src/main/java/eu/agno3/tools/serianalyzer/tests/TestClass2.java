/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 20.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.tests;


import java.io.Serializable;


@SuppressWarnings ( "all" )
public class TestClass2 implements Serializable {

    private String test;


    public void test () {
        System.out.println("Test called"); //$NON-NLS-1$
    }


    public void test2 ( Object o ) {
        System.out.println("Test2 called"); //$NON-NLS-1$
    }


    @Override
    public Object clone () {
        System.out.println("Clone called"); //$NON-NLS-1$
        return null;
    }

}