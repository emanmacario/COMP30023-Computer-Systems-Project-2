/**
 * COMP30023 Computer Systems
 * Semester 1, 2018
 * Assignment 2 - TLS Certificate Validation Using OpenSSL
 *
 * Name: Emmanuel Macario <macarioe@student.unimelb.edu.au>
 * Student Number: 831659
 * Filename: certcheck.h
 * Last Modified: 23/05/18
 *
 */
#ifndef CERTCHECK_H
#define CERTCHECK_H

// PROGRAM CONSTANTS

#define MAX_LINE_LEN 1000
#define BASIC_CONSTRAINTS_DEFAULT "CA:FALSE"
#define EXTENDED_KEY_USAGE_DEFAULT "TLS Web Server Authentication"
#define RSA_MINIMUM_KEYSIZE 2048


// FUNCTION PROTOYPES

// Takes as input an X.509 certificate, and returns
// true if the respective RSA key length is greater than 
// or equal to the default minimum length of 2048 bits.
bool validate_rsa_key_size(X509 *cert);


// Takes as input an X.509 certificate and
// returns if the 'Not Before' date is valid,
// otherwise returns false.
bool validate_not_before(X509 *cert);


// Takes as input an X.509 certificate and
// returns if the 'Not After' date is valid,
// otherwise returns false.
bool validate_not_after(X509 *cert);


// Takes as input an X.509 certificate and returns true
// if both the 'Not Before' and 'Not After' dates are valid,
// otherwise returns false.
bool validate_dates(X509 *cert);


// Takes as input a domain name as seen in the second column of the input
// csv file, and validates it against another DNS name 'pattern', which may 
// or may not include a wilcard. Returns true if there is a match, otherwise
// returns false.
bool matches(char *domain_name, char *pattern);


// Performs a validation check to see if a given domain name
// matches the certificate's 'Common Name' subject field entry. 
// Returns true if there is a match, otherwise returns false.
bool matches_common_name(char *domain_name, X509 *cert);


// Performs a validation check to see if a given domain name
// matches any of the hostnames in the certificate's 'Subject
// Alternative Name' extension.
bool matches_subject_alt_name(char *domain_name, X509 *cert);


// Performs a validation check to see if the given domain name
// matches the certificate's 'Common Name' entry, or any of the hostnames 
// in the certificate's 'Subject Alternative Name' extension. Returns
// true if the certificate is valid for the given domain name, otherwise
// returns false.
bool validate_domain_name(char *domain_name, X509 *cert);


// Performs a validation check to see if the certificate's 'Basic Constraints'
// extension contains the value 'CA:FALSE'. Returns true if so, otherwise 
// returns false.
bool validate_basic_constraints(X509 *cert);


// Performs a validation check to see if the certificate's 'Extended Key Usage'
// extension contains the value 'TLS Web Server Authentication'. Returns true 
// if so, otherwise returns false.
bool validate_ext_key_usage(X509 *cert);


// Takes as input the name of a file containing a Base64 encoded X.509
// certificate, and validates it with respect to associated domain name 
// given in the second column of the input csv file. Also validates the
// certificate's dates, RSA key size, basic constraints and extended key 
// usage values. Returns 1 if the certificate is valid, otherwise returns 0.
int validate_certificate(char *filename, char *domain_name);


#endif