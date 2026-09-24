import { Component } from 'react';

const VIDE = { erreur: null, pile: null };

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = VIDE;
    this.reprendre = this.reprendre.bind(this);
  }

  static getDerivedStateFromError(erreur) {
    return { erreur, pile: null };
  }

  componentDidCatch(erreur, info) {
    this.setState({ pile: info?.componentStack || null });
  }

  reprendre() {
    this.setState(VIDE);
    if (this.props.onRecover) this.props.onRecover();
  }

  render() {
    const { erreur, pile } = this.state;
    if (!erreur) return this.props.children;

    const l = this.props.libelles || {};
    return (
      <div className="fl-panne" role="alert">
        <p className="fl-panne-titre">{l.titre}</p>
        {l.detail ? <p className="fl-panne-detail">{l.detail}</p> : null}
        <p className="fl-panne-message">{String(erreur?.message || erreur)}</p>
        {pile ? <pre className="fl-panne-pile">{pile}</pre> : null}
        {l.action ? (
          <button type="button" className="fl-btn fl-btn-secondary fl-btn-sm" onClick={this.reprendre}>
            {l.action}
          </button>
        ) : null}
      </div>
    );
  }
}
