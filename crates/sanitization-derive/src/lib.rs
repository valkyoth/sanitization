#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, parse_quote, Attribute, Data, DataEnum, DataStruct, DeriveInput, Error,
    Fields, Generics, LitStr, Path, Result, WherePredicate,
};

/// Derive `sanitization::SecureSanitize` for structs and enums.
///
/// Every non-skipped field must implement `SecureSanitize`. Use
/// `#[sanitization(skip)]` only for fields that are intentionally non-secret or
/// cleared elsewhere.
#[proc_macro_derive(SecureSanitize, attributes(sanitization))]
pub fn derive_secure_sanitize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_secure_sanitize(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Derive `Drop` by calling `sanitization::SecureSanitize::secure_sanitize`.
///
/// # Generics
///
/// For structs with type parameters that hold sanitizable data, the parameter
/// must carry the `SecureSanitize` bound at the type declaration:
///
/// ```ignore
/// use sanitization::SecureSanitize;
///
/// #[derive(SecureSanitize, SecureSanitizeOnDrop)]
/// struct Wrapper<T: SecureSanitize> {
///     inner: T,
/// }
/// ```
///
/// This is a Rust `Drop` restriction: the generated `Drop` impl cannot add a
/// stricter `T: SecureSanitize` bound than the struct declaration itself.
#[proc_macro_derive(SecureSanitizeOnDrop, attributes(sanitization))]
pub fn derive_secure_sanitize_on_drop(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_secure_sanitize_on_drop(&input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[derive(Default)]
struct ContainerOptions {
    crate_path: Option<Path>,
    bound_override: Option<Vec<WherePredicate>>,
}

#[derive(Default)]
struct FieldOptions {
    skip: bool,
    bound_override: Option<Vec<WherePredicate>>,
}

fn expand_secure_sanitize(input: &DeriveInput) -> Result<TokenStream2> {
    let options = parse_container_options(&input.attrs)?;
    let crate_path = crate_path(&options);
    let body = match &input.data {
        Data::Struct(data) => expand_struct_body(data, &crate_path)?,
        Data::Enum(data) => expand_enum_body(data, &crate_path)?,
        Data::Union(_) => {
            return Err(Error::new_spanned(
                input,
                "SecureSanitize cannot be derived for unions; implement it manually using documented unsafe code for the active field",
            ))
        }
    };
    let generics = add_sanitize_bounds(input.generics.clone(), &input.data, &crate_path, &options)?;
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #crate_path::SecureSanitize for #name #type_generics #where_clause {
            #[inline]
            fn secure_sanitize(&mut self) {
                #body
            }
        }
    })
}

fn expand_secure_sanitize_on_drop(input: &DeriveInput) -> Result<TokenStream2> {
    let options = parse_container_options(&input.attrs)?;
    let crate_path = crate_path(&options);

    if matches!(input.data, Data::Union(_)) {
        return Err(Error::new_spanned(
            input,
            "SecureSanitizeOnDrop cannot be derived for unions",
        ));
    }

    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics Drop for #name #type_generics #where_clause {
            #[inline]
            fn drop(&mut self) {
                #crate_path::SecureSanitize::secure_sanitize(self);
            }
        }
    })
}

fn crate_path(options: &ContainerOptions) -> Path {
    options
        .crate_path
        .clone()
        .unwrap_or_else(|| parse_quote!(::sanitization))
}

fn add_sanitize_bounds(
    mut generics: Generics,
    data: &Data,
    crate_path: &Path,
    options: &ContainerOptions,
) -> Result<Generics> {
    let where_clause = generics.make_where_clause();

    if let Some(bounds) = &options.bound_override {
        where_clause.predicates.extend(bounds.iter().cloned());
        return Ok(generics);
    }

    for field in sanitized_fields(data)? {
        let field_options = parse_field_options(&field.attrs)?;
        if field_options.skip {
            continue;
        }

        if let Some(bounds) = field_options.bound_override {
            where_clause.predicates.extend(bounds);
        } else {
            let ty = &field.ty;
            where_clause
                .predicates
                .push(parse_quote!(#ty: #crate_path::SecureSanitize));
        }
    }

    Ok(generics)
}

fn sanitized_fields(data: &Data) -> Result<Vec<&syn::Field>> {
    let mut fields = Vec::new();
    match data {
        Data::Struct(data) => fields.extend(data.fields.iter()),
        Data::Enum(data) => {
            for variant in &data.variants {
                fields.extend(variant.fields.iter());
            }
        }
        Data::Union(_) => {}
    }
    Ok(fields)
}

fn expand_struct_body(data: &DataStruct, crate_path: &Path) -> Result<TokenStream2> {
    let calls = field_calls_for_struct(&data.fields, crate_path)?;
    Ok(quote!(#(#calls)*))
}

fn field_calls_for_struct(fields: &Fields, crate_path: &Path) -> Result<Vec<TokenStream2>> {
    let mut calls = Vec::new();

    for (index, field) in fields.iter().enumerate() {
        if parse_field_options(&field.attrs)?.skip {
            continue;
        }

        let access = match &field.ident {
            Some(ident) => quote!(&mut self.#ident),
            None => {
                let index = syn::Index::from(index);
                quote!(&mut self.#index)
            }
        };
        calls.push(quote!(#crate_path::SecureSanitize::secure_sanitize(#access);));
    }

    Ok(calls)
}

fn expand_enum_body(data: &DataEnum, crate_path: &Path) -> Result<TokenStream2> {
    let mut arms = Vec::new();

    for variant in &data.variants {
        let variant_ident = &variant.ident;
        let (pattern, calls) = match &variant.fields {
            Fields::Named(fields) => {
                let mut bindings = Vec::new();
                let mut calls = Vec::new();
                for field in &fields.named {
                    let ident = field.ident.as_ref().expect("named field");
                    if parse_field_options(&field.attrs)?.skip {
                        continue;
                    }
                    bindings.push(quote!(#ident));
                    calls.push(quote!(#crate_path::SecureSanitize::secure_sanitize(#ident);));
                }

                let pattern = if bindings.is_empty() {
                    quote!(Self::#variant_ident { .. })
                } else {
                    quote!(Self::#variant_ident { #(#bindings),*, .. })
                };
                (pattern, calls)
            }
            Fields::Unnamed(fields) => {
                let mut pattern_fields = Vec::new();
                let mut calls = Vec::new();
                for (index, field) in fields.unnamed.iter().enumerate() {
                    if parse_field_options(&field.attrs)?.skip {
                        pattern_fields.push(quote!(_));
                    } else {
                        let binding = format_ident!("field_{index}");
                        pattern_fields.push(quote!(#binding));
                        calls.push(quote!(#crate_path::SecureSanitize::secure_sanitize(#binding);));
                    }
                }
                (quote!(Self::#variant_ident(#(#pattern_fields),*)), calls)
            }
            Fields::Unit => (quote!(Self::#variant_ident), Vec::new()),
        };

        arms.push(quote!(#pattern => { #(#calls)* }));
    }

    Ok(quote! {
        match self {
            #(#arms),*
        }
    })
}

fn parse_container_options(attrs: &[Attribute]) -> Result<ContainerOptions> {
    let mut options = ContainerOptions::default();

    for attr in attrs
        .iter()
        .filter(|attr| attr.path().is_ident("sanitization"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("crate") {
                let value = meta.value()?;
                let literal: LitStr = value.parse()?;
                options.crate_path = Some(literal.parse()?);
                Ok(())
            } else if meta.path.is_ident("bound") {
                let value = meta.value()?;
                let literal: LitStr = value.parse()?;
                options.bound_override = Some(parse_bounds(&literal)?);
                Ok(())
            } else {
                Err(meta.error("unsupported sanitization container attribute"))
            }
        })?;
    }

    Ok(options)
}

fn parse_field_options(attrs: &[Attribute]) -> Result<FieldOptions> {
    let mut options = FieldOptions::default();

    for attr in attrs
        .iter()
        .filter(|attr| attr.path().is_ident("sanitization"))
    {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                options.skip = true;
                Ok(())
            } else if meta.path.is_ident("bound") {
                let value = meta.value()?;
                let literal: LitStr = value.parse()?;
                options.bound_override = Some(parse_bounds(&literal)?);
                Ok(())
            } else {
                Err(meta.error("unsupported sanitization field attribute"))
            }
        })?;
    }

    Ok(options)
}

fn parse_bounds(literal: &LitStr) -> Result<Vec<WherePredicate>> {
    let text = literal.value();
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    let where_clause: syn::WhereClause = syn::parse_str(&format!("where {text}"))
        .map_err(|error| Error::new(literal.span(), error))?;
    Ok(where_clause.predicates.into_iter().collect())
}
