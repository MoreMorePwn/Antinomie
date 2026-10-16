// SPDX-License-Identifier: MIT
//! Recursive-descent parser for filter expressions.
use super::*;

pub(super) struct Parser {
    pub(super) tokens: Vec<Token>,
    pub(super) at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn pop(&mut self) -> Result<Token, String> {
        let token = self
            .tokens
            .get(self.at)
            .cloned()
            .ok_or_else(|| "Filter ended early".to_owned())?;
        self.at += 1;
        Ok(token)
    }

    pub(super) fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.at += 1;
            left = Expr::Or(Box::new(left), Box::new(self.parse_and()?));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.at += 1;
            left = Expr::And(Box::new(left), Box::new(self.parse_not()?));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.at += 1;
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Token::LParen)) {
            self.at += 1;
            let inner = self.parse_or()?;
            if !matches!(self.pop()?, Token::RParen) {
                return Err("Missing closing parenthesis".into());
            }
            if let Expr::Value(left) = inner {
                if let Some(op) = self.comparison() {
                    self.at += 1;
                    return Ok(Expr::Cmp(left, op, self.parse_value()?));
                }
                return Ok(Expr::Value(left));
            }
            return Ok(inner);
        }
        if matches!(self.peek(), Some(Token::Exists | Token::Missing)) {
            let missing = matches!(self.peek(), Some(Token::Missing));
            self.at += 1;
            let parenthesized = matches!(self.peek(), Some(Token::LParen));
            if parenthesized {
                self.at += 1;
            }
            let field = self.parse_value()?;
            if parenthesized && !matches!(self.pop()?, Token::RParen) {
                return Err("Expected ) after the presence field".into());
            }
            return Ok(if missing {
                Expr::Missing(field)
            } else {
                Expr::Exists(field)
            });
        }
        let mut left = self.parse_value()?;
        if matches!(self.peek(), Some(Token::Amp)) {
            self.at += 1;
            let mask = match self.pop()? {
                Token::Number(number) if number >= 0 => {
                    u64::try_from(number).map_err(|_| "Negative mask".to_owned())?
                }
                Token::Number(_) => return Err("Negative mask".into()),
                _ => return Err("Expected a number after &".into()),
            };
            left = Value::Masked(Box::new(left), mask);
            if matches!(self.peek(), Some(Token::RParen)) {
                return Ok(Expr::Value(left));
            }
            let op = match self.pop()? {
                Token::Eq => Cmp::Eq,
                Token::Ne => Cmp::Ne,
                _ => return Err("Expected == or != after the mask".into()),
            };
            let right = self.parse_value()?;
            return Ok(Expr::Cmp(left, op, right));
        }
        if matches!(self.peek(), Some(Token::In)) {
            self.at += 1;
            return Ok(Expr::In(left, self.parse_set()?));
        }
        let op = match self.peek() {
            Some(Token::Eq) => Cmp::Eq,
            Some(Token::Ne) => Cmp::Ne,
            Some(Token::Lt) => Cmp::Lt,
            Some(Token::Le) => Cmp::Le,
            Some(Token::Gt) => Cmp::Gt,
            Some(Token::Ge) => Cmp::Ge,
            Some(Token::Contains) => Cmp::Contains,
            _ => return Ok(Expr::Value(left)),
        };
        self.at += 1;
        let right = self.parse_value()?;
        Ok(Expr::Cmp(left, op, right))
    }

    fn parse_set(&mut self) -> Result<Vec<Value>, String> {
        if !matches!(self.pop()?, Token::LBrace) {
            return Err("Expected { after in".into());
        }
        if matches!(self.peek(), Some(Token::RBrace)) {
            return Err("Empty set".into());
        }
        let mut items = Vec::new();
        loop {
            items.push(self.parse_set_item()?);
            match self.peek() {
                Some(Token::Comma) => {
                    self.at += 1;
                    if matches!(self.peek(), Some(Token::RBrace)) {
                        return Err("Expected a value in the set".into());
                    }
                }
                Some(Token::RBrace) => {
                    self.at += 1;
                    break;
                }
                _ => return Err("Expected } to close the set".into()),
            }
        }
        Ok(items)
    }

    fn parse_set_item(&mut self) -> Result<Value, String> {
        match self.pop()? {
            Token::Number(number) => Ok(Value::Number(number)),
            Token::Text(text) => Ok(Value::Text(text)),
            Token::Ident(name) => Ok(Value::Text(name)),
            _ => Err("Expected a number or quoted text in the set".into()),
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        match self.pop()? {
            Token::Ident(name) if name == "lower" => {
                if !matches!(self.pop()?, Token::LParen) {
                    return Err("Expected ( after lower".into());
                }
                let value = self.parse_value()?;
                if !matches!(self.pop()?, Token::RParen) {
                    return Err("Expected ) after lower field".into());
                }
                Ok(Value::Lower(Box::new(value)))
            }
            Token::Ident(name) if name.eq_ignore_ascii_case("args.raw") => self.parse_raw_slot(),
            Token::Ident(name) if name.to_ascii_lowercase().starts_with("args.raw[") => {
                let index = name
                    .get(9..)
                    .and_then(|suffix| suffix.strip_suffix(']'))
                    .and_then(|index| index.parse::<usize>().ok())
                    .filter(|index| *index < 6)
                    .ok_or_else(|| {
                        "args.raw slot must be an integer from 0 through 5".to_owned()
                    })?;
                Ok(Value::Raw(index))
            }
            Token::Ident(name) => Ok(Value::Field(name)),
            Token::Number(number) => Ok(Value::Number(number)),
            Token::Text(text) => Ok(Value::Text(text)),
            _ => Err("Expected a field, number or quoted text".into()),
        }
    }

    fn comparison(&self) -> Option<Cmp> {
        match self.peek()? {
            Token::Eq => Some(Cmp::Eq),
            Token::Ne => Some(Cmp::Ne),
            Token::Lt => Some(Cmp::Lt),
            Token::Le => Some(Cmp::Le),
            Token::Gt => Some(Cmp::Gt),
            Token::Ge => Some(Cmp::Ge),
            Token::Contains => Some(Cmp::Contains),
            _ => None,
        }
    }

    fn parse_raw_slot(&mut self) -> Result<Value, String> {
        if !matches!(self.peek(), Some(Token::LBracket)) {
            return Err("args.raw needs an index from 0 through 5".into());
        }
        self.at += 1;
        let index = match self.pop()? {
            Token::Number(number) if (0..6).contains(&number) => number as usize,
            Token::Number(number) => {
                return Err(format!("args.raw index {number} is outside 0 through 5"));
            }
            Token::Ident(_) => return Err("args.raw takes a slot number, not a name".into()),
            _ => return Err("args.raw needs an index from 0 through 5".into()),
        };
        if !matches!(self.pop()?, Token::RBracket) {
            return Err("Expected ] after the args.raw index".into());
        }
        Ok(Value::Raw(index))
    }
}
