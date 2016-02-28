/**
 *   This file is part of Serianalyzer.
 *
 *   Serianalyzer is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Serianalyzer is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Serianalyzer.  If not, see <http://www.gnu.org/licenses/>.
 *   
 * Copyright 2015,2016 Moritz Bechler <mbechler@eenterphace.org>
 * 
 * Created: 11.11.2015 by mbechler
 */
package serianalyzer;


/**
 * @author mbechler
 *
 */
public class SerianalyzerException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = -4093981858131960024L;


    /**
     * 
     */
    public SerianalyzerException () {}


    /**
     * @param message
     */
    public SerianalyzerException ( String message ) {
        super(message);
    }


    /**
     * @param cause
     */
    public SerianalyzerException ( Throwable cause ) {
        super(cause);
    }


    /**
     * @param message
     * @param cause
     */
    public SerianalyzerException ( String message, Throwable cause ) {
        super(message, cause);
    }


    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public SerianalyzerException ( String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace ) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
